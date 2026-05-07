// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Intel Corporation

package pfcpiface

import (
	"fmt"

	"github.com/omec-project/upf-epc/logger"
	"github.com/wmnsk/go-pfcp/ie"
)

type operation int

const (
	FwdIEOuterHeaderCreation Bits = 1 << iota
	FwdIEDestinationIntf
	FwdIEPfcpSMReqFlags
)

const (
	ActionForward = 0x2
	ActionDrop    = 0x1
	ActionBuffer  = 0x4
	ActionNotify  = 0x8
)

const (
	create operation = iota
	update
)

type far struct {
	farID   uint32
	fseID   uint64
	fseidIP uint32

	dstIntf       uint8
	sendEndMarker bool
	applyAction   uint8
	tunnelType    uint8
	tunnelIP4Src  uint32
	tunnelIP4Dst  uint32
	tunnelTEID    uint32
	tunnelPort    uint16
}

func (f far) String() string {
	return fmt.Sprintf("FAR(id=%v, F-SEID=%v, F-SEID IPv4=%v, dstInterface=%v, tunnelType=%v, "+
		"tunnelIPv4Src=%v, tunnelIPv4Dst=%v, tunnelTEID=%v, tunnelSrcPort=%v, "+
		"sendEndMarker=%v, drops=%v, forwards=%v, buffers=%v)", f.farID, f.fseID, int2ip(f.fseidIP), f.dstIntf,
		f.tunnelType, int2ip(f.tunnelIP4Src), int2ip(f.tunnelIP4Dst), f.tunnelTEID, f.tunnelPort, f.sendEndMarker,
		f.Drops(), f.Forwards(), f.Buffers())
}

func (f *far) Drops() bool {
	return f.applyAction&ActionDrop != 0
}

func (f *far) Buffers() bool {
	return f.applyAction&ActionBuffer != 0
}

func (f *far) Forwards() bool {
	return f.applyAction&ActionForward != 0
}

func (f *far) parseFAR(farIE *ie.IE, fseid uint64, upf *upf, op operation) error {
	logger.PfcpLog.Debugf("[parseFAR][Enter] F-SEID=%d Operation=%v", fseid, op)

	f.fseID = fseid

	farID, err := farIE.FARID()
	if err != nil {
		logger.PfcpLog.Errorf("[parseFAR] Failed to read FAR ID: %v", err)
		return err
	}

	f.farID = farID
	logger.PfcpLog.Debugf("[parseFAR] FAR ID=%d", farID)

	action, err := farIE.ApplyAction()
	if err != nil {
		logger.PfcpLog.Errorf("[parseFAR] Failed to read ApplyAction: %v", err)
		return err
	}

	logger.PfcpLog.Debugf("[parseFAR] ApplyAction Raw=%v", action)

	if action[0] == 0 {
		logger.PfcpLog.Errorf("[parseFAR] Invalid FAR Action=%v", action)
		return ErrInvalidArgument("FAR Action", action)
	}

	f.applyAction = action[0]

	logger.PfcpLog.Debugf(
		"[parseFAR] FARID=%d ApplyAction=%02x",
		f.farID,
		f.applyAction,
	)

	var fwdIEs []*ie.IE

	switch op {
	case create:
		logger.PfcpLog.Debugf(
			"[parseFAR] Processing CREATE FAR FARID=%d",
			f.farID,
		)

		if (f.applyAction & ActionForward) != 0 {
			logger.PfcpLog.Debugf(
				"[parseFAR] Fetching ForwardingParameters FARID=%d",
				f.farID,
			)

			fwdIEs, err = farIE.ForwardingParameters()
		}

	case update:
		logger.PfcpLog.Debugf(
			"[parseFAR] Processing UPDATE FAR FARID=%d",
			f.farID,
		)

		fwdIEs, err = farIE.UpdateForwardingParameters()

	default:
		logger.PfcpLog.Errorf(
			"[parseFAR] Invalid operation=%v FARID=%d",
			op,
			f.farID,
		)

		return ErrInvalidOperation(op)
	}

	if err != nil {
		logger.PfcpLog.Errorf(
			"[parseFAR] Failed to parse forwarding parameters FARID=%d Error=%v",
			f.farID,
			err,
		)

		return err
	}

	logger.PfcpLog.Debugf(
		"[parseFAR] FARID=%d Forwarding IE Count=%d",
		f.farID,
		len(fwdIEs),
	)

	f.sendEndMarker = false

	var fields Bits
	var ohcFields *ie.OuterHeaderCreationFields

	for i, fwdIE := range fwdIEs {
		logger.PfcpLog.Debugf(
			"[parseFAR] Processing ForwardingIE[%d] Type=%d FARID=%d",
			i,
			fwdIE.Type,
			f.farID,
		)
		switch fwdIE.Type {
		case ie.OuterHeaderCreation:
			fields = Set(fields, FwdIEOuterHeaderCreation)

			logger.PfcpLog.Debugf(
				"[parseFAR] Parsing OuterHeaderCreation FARID=%d",
				f.farID,
			)

			ohcFields, err = fwdIE.OuterHeaderCreation()
			if err != nil {
				logger.PfcpLog.Errorf(
					"[parseFAR] Unable to parse OuterHeaderCreationFields FARID=%d Error=%v",
					f.farID,
					err,
				)

				continue
			}

			f.tunnelTEID = ohcFields.TEID
			f.tunnelIP4Dst = ip2int(ohcFields.IPv4Address)
			f.tunnelType = uint8(1)
			f.tunnelPort = tunnelGTPUPort

			logger.PfcpLog.Debugf(
				"[parseFAR] FARID=%d TEID=%d DstIP=%v TunnelPort=%d",
				f.farID,
				f.tunnelTEID,
				ohcFields.IPv4Address,
				f.tunnelPort,
			)
		case ie.DestinationInterface:
			fields = Set(fields, FwdIEDestinationIntf)

			logger.PfcpLog.Debugf(
				"[parseFAR] Parsing DestinationInterface FARID=%d",
				f.farID,
			)

			f.dstIntf, err = fwdIE.DestinationInterface()
			if err != nil {
				logger.PfcpLog.Errorf(
					"[parseFAR] Unable to parse DestinationInterface FARID=%d Error=%v",
					f.farID,
					err,
				)

				continue
			}

			switch f.dstIntf {
			case ie.DstInterfaceAccess:
				f.tunnelIP4Src = ip2int(upf.accessIP)

				logger.PfcpLog.Debugf(
					"[parseFAR] FARID=%d DestinationInterface=ACCESS SrcIP=%v",
					f.farID,
					upf.accessIP,
				)

			case ie.DstInterfaceCore:
				f.tunnelIP4Src = ip2int(upf.coreIP)

				logger.PfcpLog.Debugf(
					"[parseFAR] FARID=%d DestinationInterface=CORE SrcIP=%v",
					f.farID,
					upf.coreIP,
				)

			default:
				logger.PfcpLog.Warnf(
					"[parseFAR] FARID=%d Unknown DestinationInterface=%d",
					f.farID,
					f.dstIntf,
				)
			}
		case ie.PFCPSMReqFlags:
			fields = Set(fields, FwdIEPfcpSMReqFlags)

			logger.PfcpLog.Debugf(
				"[parseFAR] Parsing PFCPSMReqFlags FARID=%d",
				f.farID,
			)

			smReqFlags, err := fwdIE.PFCPSMReqFlags()
			if err != nil {
				logger.PfcpLog.Errorf(
					"[parseFAR] Unable to parse PFCPSMReqFlags FARID=%d Error=%v",
					f.farID,
					err,
				)

				continue
			}

			logger.PfcpLog.Debugf(
				"[parseFAR] FARID=%d PFCPSMReqFlags=%08b",
				f.farID,
				smReqFlags,
			)

			if has2ndBit(smReqFlags) {
				f.sendEndMarker = true

				logger.PfcpLog.Debugf(
					"[parseFAR] FARID=%d EndMarker enabled",
					f.farID,
				)
			}
		default:
			logger.PfcpLog.Debugf(
				"[parseFAR] FARID=%d Unhandled ForwardingIE Type=%d",
				f.farID,
				fwdIE.Type,
			)
		}
	}

	logger.PfcpLog.Debugf(
		"[parseFAR][Exit] F-SEID=%d FARID=%d Action=%02x SrcIP=%d DstIP=%d TEID=%d EndMarker=%v",
		f.fseID,
		f.farID,
		f.applyAction,
		f.tunnelIP4Src,
		f.tunnelIP4Dst,
		f.tunnelTEID,
		f.sendEndMarker,
	)

	return nil
}
