// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Intel Corporation

package pfcpiface

import (
	"errors"
	"net"
	"strings"

	"github.com/omec-project/upf-epc/logger"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// errors
var (
	ErrWriteToDatapath = errors.New("write to datapath failed")
	ErrAssocNotFound   = errors.New("no association found for NodeID")
	ErrAllocateSession = errors.New("unable to allocate new PFCP session")
)

func (pConn *PFCPConn) handleSessionEstablishmentRequest(msg message.Message) (message.Message, error) {
	upf := pConn.upf

	sereq, ok := msg.(*message.SessionEstablishmentRequest)
	if !ok {
		return nil, errUnmarshal(errMsgUnexpectedType)
	}

	errUnmarshalReply := func(err error, offendingIE *ie.IE) (message.Message, error) {
		// Build response message
		pfdres := message.NewSessionEstablishmentResponse(0,
			0,
			0,
			sereq.SequenceNumber,
			0,
			ie.NewCause(ie.CauseRequestRejected),
			offendingIE,
		)

		return pfdres, errUnmarshal(err)
	}

	nodeID, err := sereq.NodeID.NodeID()
	if err != nil {
		return errUnmarshalReply(err, sereq.NodeID)
	}

	/* Read fseid from the IE */
	fseid, err := sereq.CPFSEID.FSEID()
	if err != nil {
		return errUnmarshalReply(err, sereq.CPFSEID)
	}

	remoteSEID := fseid.SEID
	fseidIP := ip2int(fseid.IPv4Address)

	errProcessReply := func(err error, cause uint8) (message.Message, error) {
		// Build response message
		seres := message.NewSessionEstablishmentResponse(0, /* MO?? <-- what's this */
			0,                    /* FO <-- what's this? */
			remoteSEID,           /* seid */
			sereq.SequenceNumber, /* seq # */
			0,                    /* priority */
			pConn.nodeID.localIE,
			ie.NewCause(cause),
		)

		return seres, errProcess(err)
	}

	if strings.Compare(nodeID, pConn.nodeID.remote) != 0 {
		logger.PfcpLog.Warnln("association not found for Establishment request",
			"with nodeID:", nodeID, ", association NodeID:", pConn.nodeID.remote)
		return errProcessReply(ErrAssocNotFound, ie.CauseNoEstablishedPFCPAssociation)
	}

	session, ok := pConn.NewPFCPSession(remoteSEID)
	if !ok {
		return errProcessReply(ErrAllocateSession,
			ie.CauseNoResourcesAvailable)
	}

	addPDRs := make([]pdr, 0, MaxItems)
	addFARs := make([]far, 0, MaxItems)
	addQERs := make([]qer, 0, MaxItems)

	for _, cPDR := range sereq.CreatePDR {
		var p pdr
		if err = p.parsePDR(cPDR, session.localSEID, pConn.appPFDs, upf.ippool); err != nil {
			return errProcessReply(err, ie.CauseRequestRejected)
		}

		if p.UPAllocateFteid {
			var fteid uint32
			// fteid, err = pConn.upf.fteidGenerator.Allocate()
			if pConn.upf.fteidGenerator == nil {
				logger.PfcpLog.Warnf("fteid is nill")
				pConn.upf.fteidGenerator = NewFTEIDGenerator()
			}
			fteid, err = pConn.upf.fteidGenerator.Allocate()
			if err != nil {
				return errProcessReply(err, ie.CauseNoResourcesAvailable)
			}
			p.tunnelTEID = fteid
			p.tunnelTEIDMask = 0xFFFFFFFF
			p.tunnelIP4Dst = ip2int(upf.accessIP)
			p.tunnelIP4DstMask = 0xFFFFFFFF
		}

		p.fseidIP = fseidIP
		session.CreatePDR(p)
		addPDRs = append(addPDRs, p)
	}

	for _, cFAR := range sereq.CreateFAR {
		var f far
		if err = f.parseFAR(cFAR, session.localSEID, upf, create); err != nil {
			return errProcessReply(err, ie.CauseRequestRejected)
		}

		f.fseidIP = fseidIP
		session.CreateFAR(f)
		addFARs = append(addFARs, f)
	}

	for _, cQER := range sereq.CreateQER {
		var q qer
		if err = q.parseQER(cQER, session.localSEID); err != nil {
			return errProcessReply(err, ie.CauseRequestRejected)
		}

		q.fseidIP = fseidIP
		session.CreateQER(q)
		addQERs = append(addQERs, q)
	}

	session.MarkSessionQer(session.qers)
	// FIXME: since PacketForwardingRules doesn't store pointers,
	//  we must also mark session QERs in addQERs.
	//  We need a kind of refactoring to clean it up.
	session.MarkSessionQer(addQERs)

	// session.PacketForwardingRules stores all PFCP rules that has been installed so far,
	// while 'updated' stores only the PFCP rules that have been provided in this particular message.
	updated := PacketForwardingRules{
		pdrs: addPDRs,
		fars: addFARs,
		qers: addQERs,
	}

	cause := upf.SendMsgToUPF(upfMsgTypeAdd, session.PacketForwardingRules, updated)
	if cause != ie.CauseRequestAccepted {
		pConn.RemoveSession(session)
		return errProcessReply(ErrWriteToDatapath,
			cause)
	}

	err = pConn.store.PutSession(session)
	if err != nil {
		logger.PfcpLog.Errorf("failed to put PFCP session to store: %v", err)
	}

	var localFSEID *ie.IE

	localIP := pConn.LocalAddr().(*net.UDPAddr).IP
	if localIP.To4() != nil {
		localFSEID = ie.NewFSEID(session.localSEID, localIP, nil)
	} else {
		localFSEID = ie.NewFSEID(session.localSEID, nil, localIP)
	}

	// Build response message
	seres := message.NewSessionEstablishmentResponse(0, /* MO?? <-- what's this */
		0,                                    /* FO <-- what's this? */
		session.remoteSEID,                   /* seid */
		sereq.SequenceNumber,                 /* seq # */
		0,                                    /* priority */
		pConn.nodeID.localIE,                 /* node id */
		ie.NewCause(ie.CauseRequestAccepted), /* accept it blindly for the time being */
		localFSEID,
	)
	addPdrInfo(seres, addPDRs)

	return seres, nil
}

func (pConn *PFCPConn) handleSessionModificationRequest(msg message.Message) (message.Message, error) {
	upf := pConn.upf

	smreq, ok := msg.(*message.SessionModificationRequest)
	if !ok {
		return nil, errUnmarshal(errMsgUnexpectedType)
	}

	var remoteSEID uint64

	sendError := func(err error, cause uint8) (message.Message, error) {
		logger.PfcpLog.Errorf("sendError: cause=%d err=%v", cause, err)

		smres := message.NewSessionModificationResponse(0, /* MO?? <-- what's this */
			0,                    /* FO <-- what's this? */
			remoteSEID,           /* seid */
			smreq.SequenceNumber, /* seq # */
			0,                    /* priority */
			ie.NewCause(cause),
		)

		return smres, err
	}

	localSEID := smreq.SEID()
	logger.PfcpLog.Debugf("handleSessionModificationRequest: localSEID=%d seq=%d", localSEID, smreq.SequenceNumber)

	session, ok := pConn.store.GetSession(localSEID)
	if !ok {
		logger.PfcpLog.Errorf("session not found for localSEID=%d", localSEID)
		return sendError(ErrNotFoundWithParam("PFCP session", "localSEID", localSEID), ie.CauseRequestRejected)
	}
	logger.PfcpLog.Debugf("session found: localSEID=%d remoteSEID=%d", localSEID, session.remoteSEID)
	var fseidIP uint32

	if smreq.CPFSEID != nil {
		fseid, err := smreq.CPFSEID.FSEID()
		if err == nil {
			session.remoteSEID = fseid.SEID
			fseidIP = ip2int(fseid.IPv4Address)
			logger.PfcpLog.Debugf("CPFSEID present: remoteSEID updated to %d, fseidIP=%d", fseid.SEID, fseidIP)

			logger.PfcpLog.Debugln("updated FSEID from session modification request")
		} else {
			logger.PfcpLog.Warnf("CPFSEID parse failed: %v", err)
		}
	} else {
		logger.PfcpLog.Debugf("no CPFSEID in request")
	}

	remoteSEID = session.remoteSEID

	logger.PfcpLog.Debugf("IE counts — CreatePDR:%d CreateFAR:%d CreateQER:%d | UpdatePDR:%d UpdateFAR:%d UpdateQER:%d | RemovePDR:%d RemoveFAR:%d RemoveQER:%d",
		len(smreq.CreatePDR), len(smreq.CreateFAR), len(smreq.CreateQER),
		len(smreq.UpdatePDR), len(smreq.UpdateFAR), len(smreq.UpdateQER),
		len(smreq.RemovePDR), len(smreq.RemoveFAR), len(smreq.RemoveQER))

	addPDRs := make([]pdr, 0, MaxItems)
	addFARs := make([]far, 0, MaxItems)
	addQERs := make([]qer, 0, MaxItems)
	endMarkerList := make([][]byte, 0, MaxItems)

	logger.PfcpLog.Debugf(
		"[PFCP][SessionModification] Processing CreatePDR Count=%d LocalSEID=%d",
		len(smreq.CreatePDR),
		localSEID,
	)

	for i, cPDR := range smreq.CreatePDR {
		logger.PfcpLog.Infof("[PFCP][CreatePDR] Parsing CreatePDR[%d]", i)

		var p pdr
		if err := p.parsePDR(cPDR, localSEID, pConn.appPFDs, upf.ippool); err != nil {
			logger.PfcpLog.Errorf(
				"[PFCP][CreatePDR] Failed Parse Index=%d LocalSEID=%d Error=%v",
				i,
				localSEID,
				err,
			)
			return sendError(err, ie.CauseRequestRejected)
		}

		p.fseidIP = fseidIP

		session.CreatePDR(p)
		addPDRs = append(addPDRs, p)

		logger.PfcpLog.Debugf(
			"[PFCP][CreatePDR] Success PDRID=%d FARID=%d QERCount=%d",
			p.pdrID,
			p.farID,
			len(p.qerIDList),
		)
	}

	logger.PfcpLog.Debugf("[PFCP][CreatePDR] Total Added PDRs=%d", len(addPDRs))

	// =========================
	// Create FAR
	// =========================
	logger.PfcpLog.Debugf(
		"[PFCP][SessionModification] Processing CreateFAR Count=%d",
		len(smreq.CreateFAR),
	)

	for i, cFAR := range smreq.CreateFAR {
		logger.PfcpLog.Debugf("[PFCP][CreateFAR] Parsing CreateFAR[%d]", i)

		var f far
		if err := f.parseFAR(cFAR, localSEID, upf, create); err != nil {
			logger.PfcpLog.Errorf(
				"[PFCP][CreateFAR] Failed Parse Index=%d Error=%v",
				i,
				err,
			)
			return sendError(err, ie.CauseRequestRejected)
		}

		f.fseidIP = fseidIP

		session.CreateFAR(f)
		addFARs = append(addFARs, f)

		logger.PfcpLog.Debugf(
			"[PFCP][CreateFAR] Success FARID=%d Action=%02x",
			f.farID,
			f.applyAction,
		)
	}

	// =========================
	// Create QER
	// =========================
	logger.PfcpLog.Debugf(
		"[PFCP][SessionModification] Processing CreateQER Count=%d",
		len(smreq.CreateQER),
	)

	for i, cQER := range smreq.CreateQER {
		logger.PfcpLog.Debugf("[PFCP][CreateQER] Parsing CreateQER[%d]", i)

		var q qer
		if err := q.parseQER(cQER, localSEID); err != nil {
			logger.PfcpLog.Errorf(
				"[PFCP][CreateQER] Failed Parse Index=%d Error=%v",
				i,
				err,
			)
			return sendError(err, ie.CauseRequestRejected)
		}

		q.fseidIP = fseidIP

		session.CreateQER(q)
		addQERs = append(addQERs, q)

		logger.PfcpLog.Debugf(
			"[PFCP][CreateQER] Success QERID=%d",
			q.qerID,
		)
	}

	// =========================
	// Update PDR
	// =========================
	logger.PfcpLog.Debugf(
		"[PFCP][SessionModification] Processing UpdatePDR Count=%d",
		len(smreq.UpdatePDR),
	)

	for i, uPDR := range smreq.UpdatePDR {
		logger.PfcpLog.Infof("[PFCP][UpdatePDR] Parsing UpdatePDR[%d]", i)

		var (
			p   pdr
			err error
		)

		if err = p.parsePDR(uPDR, localSEID, pConn.appPFDs, upf.ippool); err != nil {
			logger.PfcpLog.Errorf(
				"[PFCP][UpdatePDR] Parse Failed Index=%d Error=%v",
				i,
				err,
			)
			return sendError(err, ie.CauseRequestRejected)
		}

		p.fseidIP = fseidIP

		err = session.UpdatePDR(p)
		if err != nil {
			logger.PfcpLog.Errorf(
				"[PFCP][UpdatePDR] Session Update Failed PDRID=%d Error=%v",
				p.pdrID,
				err,
			)
			continue
		}

		addPDRs = append(addPDRs, p)

		logger.PfcpLog.Debugf(
			"[PFCP][UpdatePDR] Success PDRID=%d",
			p.pdrID,
		)
	}

	// =========================
	// Update FAR
	// =========================
	logger.PfcpLog.Debugf(
		"[PFCP][SessionModification] Processing UpdateFAR Count=%d",
		len(smreq.UpdateFAR),
	)

	for i, uFAR := range smreq.UpdateFAR {
		logger.PfcpLog.Debugf("[PFCP][UpdateFAR] Parsing UpdateFAR[%d]", i)

		var (
			f   far
			err error
		)

		farID, err := uFAR.FARID()
		if err != nil {
			logger.PfcpLog.Errorf(
				"[PFCP][UpdateFAR] Failed to read FARID Index=%d Error=%v",
				i,
				err,
			)
			return sendError(err, ie.CauseMandatoryIEIncorrect)
		}

		logger.PfcpLog.Infof(
			"[PFCP][UpdateFAR] Received FARID=%d",
			farID,
		)

		farExists := false

		for _, existingFAR := range session.fars {
			if existingFAR.farID == farID {
				farExists = true
				break
			}
		}

		if !farExists {
			logger.PfcpLog.Warnf(
				"[PFCP][UpdateFAR] FARID=%d not found for LocalSEID=%d",
				farID,
				localSEID,
			)

			return sendError(
				errors.New("invalid forwarding policy: FAR ID not found"),
				ie.CauseInvalidForwardingPolicy,
			)
		}

		if err = f.parseFAR(uFAR, localSEID, upf, update); err != nil {
			logger.PfcpLog.Errorf(
				"[PFCP][UpdateFAR] Parse Failed FARID=%d Error=%v",
				farID,
				err,
			)
			return sendError(err, ie.CauseRequestRejected)
		}

		f.fseidIP = fseidIP

		err = session.UpdateFAR(&f, &endMarkerList)
		if err != nil {
			logger.PfcpLog.Errorf(
				"[PFCP][UpdateFAR] Session Update Failed FARID=%d Error=%v",
				f.farID,
				err,
			)
			return sendError(err, ie.CauseRequestRejected)
		}

		addFARs = append(addFARs, f)

		logger.PfcpLog.Debugf(
			"[PFCP][UpdateFAR] Success FARID=%d EndMarker=%v",
			f.farID,
			f.sendEndMarker,
		)
	}

	// =========================
	// Update QER
	// =========================
	logger.PfcpLog.Debugf(
		"[PFCP][SessionModification] Processing UpdateQER Count=%d",
		len(smreq.UpdateQER),
	)

	for i, uQER := range smreq.UpdateQER {
		logger.PfcpLog.Debugf("[PFCP][UpdateQER] Parsing UpdateQER[%d]", i)

		var (
			q   qer
			err error
		)

		if err = q.parseQER(uQER, localSEID); err != nil {
			logger.PfcpLog.Errorf(
				"[PFCP][UpdateQER] Parse Failed Index=%d Error=%v",
				i,
				err,
			)
			return sendError(err, ie.CauseRequestRejected)
		}

		q.fseidIP = fseidIP

		err = session.UpdateQER(q)
		if err != nil {
			logger.PfcpLog.Errorf(
				"[PFCP][UpdateQER] Session Update Failed QERID=%d Error=%v",
				q.qerID,
				err,
			)
			continue
		}

		addQERs = append(addQERs, q)

		logger.PfcpLog.Debugf(
			"[PFCP][UpdateQER] Success QERID=%d",
			q.qerID,
		)
	}

	logger.PfcpLog.Debugf(
		"[PFCP][SessionModification] Marking Session QERs TotalSessionQERs=%d AddedQERs=%d",
		len(session.qers),
		len(addQERs),
	)

	session.MarkSessionQer(session.qers)
	session.MarkSessionQer(addQERs)

	updated := PacketForwardingRules{
		pdrs: addPDRs,
		fars: addFARs,
		qers: addQERs,
	}

	logger.PfcpLog.Debugf(
		"[PFCP][SessionModification] Sending Rules To Datapath AddPDRs=%d AddFARs=%d AddQERs=%d",
		len(addPDRs),
		len(addFARs),
		len(addQERs),
	)

	cause := upf.SendMsgToUPF(upfMsgTypeMod, session.PacketForwardingRules, updated)

	logger.PfcpLog.Debugf(
		"[PFCP][SessionModification] Datapath Response Cause=%d",
		cause,
	)

	if cause == ie.CauseRequestRejected {
		logger.PfcpLog.Errorf("[PFCP][SessionModification] Datapath rejected modification")
		return sendError(ErrWriteToDatapath, cause)
	}

	if upf.enableEndMarker {
		logger.PfcpLog.Debugf(
			"[PFCP][SessionModification] Sending EndMarkers Count=%d",
			len(endMarkerList),
		)

		err := upf.SendEndMarkers(&endMarkerList)
		if err != nil {
			logger.PfcpLog.Errorln("sending End Markers Failed:", err)
		}
	}

	delPDRs := make([]pdr, 0, MaxItems)
	delFARs := make([]far, 0, MaxItems)
	delQERs := make([]qer, 0, MaxItems)

	// =========================
	// Remove PDR
	// =========================
	logger.PfcpLog.Debugf(
		"[PFCP][SessionModification] Processing RemovePDR Count=%d",
		len(smreq.RemovePDR),
	)

	for i, rPDR := range smreq.RemovePDR {
		logger.PfcpLog.Debugf("[PFCP][RemovePDR] Processing RemovePDR[%d]", i)

		pdrID, err := rPDR.PDRID()
		if err != nil {
			logger.PfcpLog.Errorf(
				"[PFCP][RemovePDR] Failed to read PDRID Index=%d Error=%v",
				i,
				err,
			)
			return sendError(err, ie.CauseRequestRejected)
		}

		logger.PfcpLog.Debugf(
			"[PFCP][RemovePDR] Removing PDRID=%d",
			pdrID,
		)

		p, err := session.RemovePDR(uint32(pdrID))
		if err != nil {
			logger.PfcpLog.Errorf(
				"[PFCP][RemovePDR] Session Remove Failed PDRID=%d Error=%v",
				pdrID,
				err,
			)
			return sendError(err, ie.CauseRequestRejected)
		}

		delPDRs = append(delPDRs, *p)

		logger.PfcpLog.Debugf(
			"[PFCP][RemovePDR] Success PDRID=%d",
			pdrID,
		)
	}

	// =========================
	// Remove FAR
	// =========================
	logger.PfcpLog.Debugf(
		"[PFCP][SessionModification] Processing RemoveFAR Count=%d",
		len(smreq.RemoveFAR),
	)

	for i, dFAR := range smreq.RemoveFAR {
		logger.PfcpLog.Debugf("[PFCP][RemoveFAR] Processing RemoveFAR[%d]", i)

		farID, err := dFAR.FARID()
		if err != nil {
			logger.PfcpLog.Errorf(
				"[PFCP][RemoveFAR] Failed to read FARID Index=%d Error=%v",
				i,
				err,
			)
			return sendError(err, ie.CauseRequestRejected)
		}

		logger.PfcpLog.Debugf(
			"[PFCP][RemoveFAR] Removing FARID=%d",
			farID,
		)

		f, err := session.RemoveFAR(farID)
		if err != nil {
			logger.PfcpLog.Errorf(
				"[PFCP][RemoveFAR] Session Remove Failed FARID=%d Error=%v",
				farID,
				err,
			)
			return sendError(err, ie.CauseRequestRejected)
		}

		delFARs = append(delFARs, *f)

		logger.PfcpLog.Debugf(
			"[PFCP][RemoveFAR] Success FARID=%d",
			farID,
		)
	}

	// =========================
	// Remove QER
	// =========================
	logger.PfcpLog.Debugf(
		"[PFCP][SessionModification] Processing RemoveQER Count=%d",
		len(smreq.RemoveQER),
	)

	for i, dQER := range smreq.RemoveQER {
		logger.PfcpLog.Debugf("[PFCP][RemoveQER] Processing RemoveQER[%d]", i)

		qerID, err := dQER.QERID()
		if err != nil {
			logger.PfcpLog.Errorf(
				"[PFCP][RemoveQER] Failed to read QERID Index=%d Error=%v",
				i,
				err,
			)
			return sendError(err, ie.CauseRequestRejected)
		}

		logger.PfcpLog.Debugf(
			"[PFCP][RemoveQER] Removing QERID=%d",
			qerID,
		)

		q, err := session.RemoveQER(qerID)
		if err != nil {
			logger.PfcpLog.Errorf(
				"[PFCP][RemoveQER] Session Remove Failed QERID=%d Error=%v",
				qerID,
				err,
			)
			return sendError(err, ie.CauseRequestRejected)
		}

		delQERs = append(delQERs, *q)

		logger.PfcpLog.Debugf(
			"[PFCP][RemoveQER] Success QERID=%d",
			qerID,
		)
	}

	// =========================
	// Send Delete Rules To Datapath
	// =========================
	deleted := PacketForwardingRules{
		pdrs: delPDRs,
		fars: delFARs,
		qers: delQERs,
	}

	logger.PfcpLog.Debugf(
		"[PFCP][SessionModification] Sending Delete Rules To Datapath DelPDRs=%d DelFARs=%d DelQERs=%d",
		len(delPDRs),
		len(delFARs),
		len(delQERs),
	)

	cause = upf.SendMsgToUPF(upfMsgTypeDel, deleted, PacketForwardingRules{})

	logger.PfcpLog.Debugf(
		"[PFCP][SessionModification] Delete Datapath Response Cause=%d",
		cause,
	)

	if cause == ie.CauseRequestRejected {
		logger.PfcpLog.Errorf(
			"[PFCP][SessionModification] Datapath rejected delete request",
		)
		return sendError(ErrWriteToDatapath, cause)
	}

	// =========================
	// Store Session
	// =========================
	logger.PfcpLog.Debugf(
		"[PFCP][SessionModification] Storing PFCP Session LocalSEID=%d",
		localSEID,
	)

	err := pConn.store.PutSession(session)
	if err != nil {
		logger.PfcpLog.Errorf(
			"failed to put PFCP session to store: %v",
			err,
		)
	} else {
		logger.PfcpLog.Debugf(
			"[PFCP][SessionModification] Successfully stored PFCP Session LocalSEID=%d",
			localSEID,
		)
	}

	// =========================
	// Build Session Modification Response
	// =========================
	logger.PfcpLog.Debugf(
		"[PFCP][SessionModification] Building SessionModificationResponse RemoteSEID=%d Seq=%d",
		remoteSEID,
		smreq.SequenceNumber,
	)

	smres := message.NewSessionModificationResponse(
		0,                                    /* MO */
		0,                                    /* FO */
		remoteSEID,                           /* seid */
		smreq.SequenceNumber,                 /* seq # */
		0,                                    /* priority */
		ie.NewCause(ie.CauseRequestAccepted), /* accepted */
	)

	logger.PfcpLog.Debugf(
		"[PFCP][SessionModification] SessionModificationResponse Created Successfully",
	)

	return smres, nil
}

func (pConn *PFCPConn) handleSessionDeletionRequest(msg message.Message) (message.Message, error) {
	upf := pConn.upf

	sdreq, ok := msg.(*message.SessionDeletionRequest)
	if !ok {
		return nil, errUnmarshal(errMsgUnexpectedType)
	}

	sendError := func(err error) (message.Message, error) {
		smres := message.NewSessionDeletionResponse(0, /* MO?? <-- what's this */
			0,                    /* FO <-- what's this? */
			0,                    /* seid */
			sdreq.SequenceNumber, /* seq # */
			0,                    /* priority */
			ie.NewCause(ie.CauseSessionContextNotFound), /* accept it blindly for the time being */
		)

		return smres, err
	}

	/* retrieve sessionRecord */
	localSEID := sdreq.SEID()

	session, ok := pConn.store.GetSession(localSEID)
	if !ok {
		return sendError(ErrNotFoundWithParam("PFCP session", "localSEID", localSEID))
	}

	cause := upf.SendMsgToUPF(upfMsgTypeDel, session.PacketForwardingRules, PacketForwardingRules{})
	if cause == ie.CauseRequestRejected {
		return sendError(ErrWriteToDatapath)
	}

	if err := releaseAllocatedIPs(upf.ippool, &session); err != nil {
		return sendError(ErrOperationFailedWithReason("session IP dealloc", err.Error()))
	}

	/* delete sessionRecord */
	pConn.RemoveSession(session)

	// Build response message
	smres := message.NewSessionDeletionResponse(0, /* MO?? <-- what's this */
		0,                                    /* FO <-- what's this? */
		session.remoteSEID,                   /* seid */
		sdreq.SequenceNumber,                 /* seq # */
		0,                                    /* priority */
		ie.NewCause(ie.CauseRequestAccepted), /* accept it blindly for the time being */
	)

	return smres, nil
}

func (pConn *PFCPConn) handleDigestReport(fseid uint64) {
	session, ok := pConn.store.GetSession(fseid)
	if !ok {
		logger.PfcpLog.Warnln("no session found for fseid:", fseid)
		return
	}

	seq := pConn.getSeqNum()
	srreq := message.NewSessionReportRequest(0, /* MO?? <-- what's this */
		0,                            /* FO <-- what's this? */
		0,                            /* seid */
		seq,                          /* seq # */
		0,                            /* priority */
		ie.NewReportType(0, 0, 0, 1), /*upir, erir, usar, dldr int*/
	)
	srreq.Header.SEID = session.remoteSEID

	var pdrID uint32

	var farID uint32

	for _, pdr := range session.pdrs {
		if pdr.srcIface == core {
			pdrID = pdr.pdrID

			farID = pdr.farID

			break
		}
	}

	for _, far := range session.fars {
		if far.farID == farID {
			if far.applyAction&ActionNotify == 0 {
				logger.PfcpLog.Errorln("packet received for forwarding far. discard")
				return
			}
		}
	}

	if pdrID == 0 {
		logger.PfcpLog.Errorln("no Pdr found for downlink")

		return
	}

	srreq.DownlinkDataReport = ie.NewDownlinkDataReport(
		ie.NewPDRID(uint16(pdrID)))

	logger.PfcpLog.With("F-SEID", fseid, "PDR ID", pdrID).Debugln("sending Downlink Data Report")

	pConn.SendPFCPMsg(srreq)
}

func (pConn *PFCPConn) handleSessionReportResponse(msg message.Message) error {
	upf := pConn.upf

	srres, ok := msg.(*message.SessionReportResponse)
	if !ok {
		return errUnmarshal(errMsgUnexpectedType)
	}

	cause := srres.Cause.Payload[0]
	if cause == ie.CauseRequestAccepted {
		return nil
	}

	logger.PfcpLog.Warnln("session req not accepted seq:", srres.SequenceNumber)

	seid := srres.SEID()

	if cause == ie.CauseSessionContextNotFound {
		sessItem, ok := pConn.store.GetSession(seid)
		if !ok {
			return errProcess(ErrNotFoundWithParam("PFCP session context", "SEID", seid))
		}

		logger.PfcpLog.Warnln("context not found, deleting session locally")

		pConn.RemoveSession(sessItem)

		cause := upf.SendMsgToUPF(
			upfMsgTypeDel, sessItem.PacketForwardingRules, PacketForwardingRules{})
		if cause == ie.CauseRequestRejected {
			return errProcess(
				ErrOperationFailedWithParam("delete session from datapath", "seid", seid))
		}

		return nil
	}

	return nil
}
