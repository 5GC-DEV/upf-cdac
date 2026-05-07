// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Intel Corporation

package pfcpiface

import (
	"fmt"

	"github.com/omec-project/upf-epc/logger"
	"github.com/wmnsk/go-pfcp/ie"
)

var qosLevelName = map[QosLevel]string{
	ApplicationQos: "application",
	SessionQos:     "session",
}

type qer struct {
	qerID    uint32
	qosLevel QosLevel
	qfi      uint8
	ulStatus uint8
	dlStatus uint8
	ulMbr    uint64 // in kilobits/sec
	dlMbr    uint64 // in kilobits/sec
	ulGbr    uint64 // in kilobits/sec
	dlGbr    uint64 // in kilobits/sec
	fseID    uint64
	fseidIP  uint32
}

func (q qer) String() string {
	qosLevel, ok := qosLevelName[q.qosLevel]
	if !ok {
		qosLevel = "invalid"
	}

	return fmt.Sprintf("QER(id=%v, F-SEID=%v, F-SEID IP=%v, QFI=%v, "+
		"uplinkMBR=%v, downlinkMBR=%v, uplinkGBR=%v, downlinkGBR=%v, type=%s, "+
		"uplinkStatus=%v, downlinkStatus=%v)",
		q.qerID, q.fseID, q.fseidIP, q.qfi, q.ulMbr, q.dlMbr, q.ulGbr, q.dlGbr,
		qosLevel, q.ulStatus, q.dlStatus)
}

func (q *qer) parseQER(ie1 *ie.IE, seid uint64) error {
	logger.PfcpLog.Debugf("[parseQER][Enter] F-SEID=%d", seid)

	qerID, err := ie1.QERID()
	if err != nil {
		logger.PfcpLog.Errorf("[parseQER] Could not read QER ID: %v", err)
		return err
	}

	logger.PfcpLog.Debugf("[parseQER] QERID=%d", qerID)

	qfi, err := ie1.QFI()
	if err != nil {
		logger.PfcpLog.Errorf(
			"[parseQER] Could not read QFI QERID=%d Error=%v",
			qerID,
			err,
		)
	} else {
		logger.PfcpLog.Debugf(
			"[parseQER] QERID=%d QFI=%d",
			qerID,
			qfi,
		)
	}

	gsUL, err := ie1.GateStatusUL()
	if err != nil {
		logger.PfcpLog.Errorf(
			"[parseQER] Could not read Gate status uplink QERID=%d Error=%v",
			qerID,
			err,
		)
	} else {
		logger.PfcpLog.Debugf(
			"[parseQER] QERID=%d UL Gate Status=%d",
			qerID,
			gsUL,
		)
	}

	gsDL, err := ie1.GateStatusDL()
	if err != nil {
		logger.PfcpLog.Errorf(
			"[parseQER] Could not read Gate status downlink QERID=%d Error=%v",
			qerID,
			err,
		)
	} else {
		logger.PfcpLog.Debugf(
			"[parseQER] QERID=%d DL Gate Status=%d",
			qerID,
			gsDL,
		)
	}

	mbrUL, err := ie1.MBRUL()
	if err != nil {
		logger.PfcpLog.Errorf(
			"[parseQER] Could not read MBRUL QERID=%d Error=%v",
			qerID,
			err,
		)
	} else {
		logger.PfcpLog.Debugf(
			"[parseQER] QERID=%d UL MBR=%d",
			qerID,
			mbrUL,
		)
	}

	mbrDL, err := ie1.MBRDL()
	if err != nil {
		logger.PfcpLog.Errorf(
			"[parseQER] Could not read MBRDL QERID=%d Error=%v",
			qerID,
			err,
		)
	} else {
		logger.PfcpLog.Debugf(
			"[parseQER] QERID=%d DL MBR=%d",
			qerID,
			mbrDL,
		)
	}

	gbrUL, err := ie1.GBRUL()
	if err != nil {
		logger.PfcpLog.Warnf(
			"[parseQER] Could not read GBRUL QERID=%d. It might be a non-GBR flow. Error=%v",
			qerID,
			err,
		)
	} else {
		logger.PfcpLog.Debugf(
			"[parseQER] QERID=%d UL GBR=%d",
			qerID,
			gbrUL,
		)
	}

	gbrDL, err := ie1.GBRDL()
	if err != nil {
		logger.PfcpLog.Warnf(
			"[parseQER] Could not read GBRDL QERID=%d. It might be a non-GBR flow. Error=%v",
			qerID,
			err,
		)
	} else {
		logger.PfcpLog.Debugf(
			"[parseQER] QERID=%d DL GBR=%d",
			qerID,
			gbrDL,
		)
	}

	q.qerID = qerID
	q.qfi = qfi
	q.ulStatus = gsUL
	q.dlStatus = gsDL
	q.ulMbr = mbrUL
	q.dlMbr = mbrDL
	q.ulGbr = gbrUL
	q.dlGbr = gbrDL
	q.fseID = seid

	logger.PfcpLog.Debugf(
		"[parseQER][Exit] F-SEID=%d QERID=%d QFI=%d ULStatus=%d DLStatus=%d ULMBR=%d DLMBR=%d ULGBR=%d DLGBR=%d",
		q.fseID,
		q.qerID,
		q.qfi,
		q.ulStatus,
		q.dlStatus,
		q.ulMbr,
		q.dlMbr,
		q.ulGbr,
		q.dlGbr,
	)

	return nil
}
