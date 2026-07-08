// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/omec-project/ngap/v2/aper"
	"github.com/omec-project/ngap/v2/ngapType"
	"github.com/omec-project/openapi/v2/models"
)

func HandlePDUSessionResourceSetupResponseTransfer(b []byte, ctx *SMContext) (err error) {
	resourceSetupResponseTransfer := ngapType.PDUSessionResourceSetupResponseTransfer{}

	err = aper.UnmarshalWithParams(b, &resourceSetupResponseTransfer, "valueExt")
	if err != nil {
		return err
	}

	QosFlowPerTNLInformation := resourceSetupResponseTransfer.DLQosFlowPerTNLInformation

	if QosFlowPerTNLInformation.UPTransportLayerInformation.Present !=
		ngapType.UPTransportLayerInformationPresentGTPTunnel {
		return errors.New("resourceSetupResponseTransfer.QosFlowPerTNLInformation.UPTransportLayerInformation.Present")
	}

	gtpTunnel := QosFlowPerTNLInformation.UPTransportLayerInformation.GTPTunnel

	teid := binary.BigEndian.Uint32(gtpTunnel.GTPTEID.Value)

	ctx.Tunnel.ANInformation.IPAddress = gtpTunnel.TransportLayerAddress.Value.Bytes
	ctx.Tunnel.ANInformation.TEID = teid

	for _, dataPath := range ctx.Tunnel.DataPathPool {
		if dataPath.Activated {
			ANUPF := dataPath.FirstDPNode
			for _, DLPDR := range ANUPF.DownLinkTunnel.PDR {
				DLPDR.FAR.ForwardingParameters.OuterHeaderCreation = new(OuterHeaderCreation)
				dlOuterHeaderCreation := DLPDR.FAR.ForwardingParameters.OuterHeaderCreation
				dlOuterHeaderCreation.OuterHeaderCreationDescription = OuterHeaderCreationGtpUUdpIpv4
				dlOuterHeaderCreation.Teid = teid
				dlOuterHeaderCreation.Ipv4Address = ctx.Tunnel.ANInformation.IPAddress.To4()
			}
		}
	}

	ctx.UpCnxState = models.UPCNXSTATE_ACTIVATED
	return nil
}

func HandlePathSwitchRequestTransfer(b []byte, ctx *SMContext) error {
	pathSwitchRequestTransfer := ngapType.PathSwitchRequestTransfer{}

	if err := aper.UnmarshalWithParams(b, &pathSwitchRequestTransfer, "valueExt"); err != nil {
		return err
	}

	if pathSwitchRequestTransfer.DLNGUUPTNLInformation.Present != ngapType.UPTransportLayerInformationPresentGTPTunnel {
		return errors.New("pathSwitchRequestTransfer.DLNGUUPTNLInformation.Present")
	}

	gtpTunnel := pathSwitchRequestTransfer.DLNGUUPTNLInformation.GTPTunnel

	teid := binary.BigEndian.Uint32(gtpTunnel.GTPTEID.Value)

	ctx.Tunnel.ANInformation.IPAddress = gtpTunnel.TransportLayerAddress.Value.Bytes
	ctx.Tunnel.ANInformation.TEID = teid

	for _, dataPath := range ctx.Tunnel.DataPathPool {
		if dataPath.Activated {
			ANUPF := dataPath.FirstDPNode
			for _, DLPDR := range ANUPF.DownLinkTunnel.PDR {
				DLPDR.FAR.ForwardingParameters.OuterHeaderCreation = new(OuterHeaderCreation)
				dlOuterHeaderCreation := DLPDR.FAR.ForwardingParameters.OuterHeaderCreation
				dlOuterHeaderCreation.OuterHeaderCreationDescription = OuterHeaderCreationGtpUUdpIpv4
				dlOuterHeaderCreation.Teid = teid
				dlOuterHeaderCreation.Ipv4Address = gtpTunnel.TransportLayerAddress.Value.Bytes
				DLPDR.FAR.State = RULE_UPDATE
				DLPDR.FAR.ForwardingParameters.PFCPSMReqFlags = new(PFCPSMReqFlags)
				DLPDR.FAR.ForwardingParameters.PFCPSMReqFlags.Sndem = true
			}
		}
	}

	return nil
}

func HandlePathSwitchRequestSetupFailedTransfer(b []byte, ctx *SMContext) (err error) {
	pathSwitchRequestSetupFailedTransfer := ngapType.PathSwitchRequestSetupFailedTransfer{}

	err = aper.UnmarshalWithParams(b, &pathSwitchRequestSetupFailedTransfer, "valueExt")
	if err != nil {
		return err
	}

	// TODO: finish handler
	return nil
}

func HandleHandoverRequiredTransfer(b []byte, ctx *SMContext) (err error) {
	handoverRequiredTransfer := ngapType.HandoverRequiredTransfer{}

	err = aper.UnmarshalWithParams(b, &handoverRequiredTransfer, "valueExt")
	if err != nil {
		return err
	}

	// TODO: Handle Handover Required Transfer
	return nil
}

func HandleHandoverRequestAcknowledgeTransfer(b []byte, ctx *SMContext) (err error) {
	handoverRequestAcknowledgeTransfer := ngapType.HandoverRequestAcknowledgeTransfer{}

	err = aper.UnmarshalWithParams(b, &handoverRequestAcknowledgeTransfer, "valueExt")
	if err != nil {
		return err
	}
	DLNGUUPTNLInformation := handoverRequestAcknowledgeTransfer.DLNGUUPTNLInformation
	GTPTunnel := DLNGUUPTNLInformation.GTPTunnel

	// The GTP-TEID is a fixed 4-octet big-endian value. Reading it as a LEB128
	// varint (binary.ReadUvarint) stopped at the first 0x00 byte, so any TEID
	// below 2^24 (i.e. almost all of them) decoded to 0 — leaving the downlink
	// FAR at TEID 0, so the UPF never forwarded downlink to the target gNB after
	// an N2 handover. Every other TEID read in this file uses BigEndian.Uint32.
	if len(GTPTunnel.GTPTEID.Value) != 4 {
		return fmt.Errorf("GTP-TEID must be 4 octets, got %d", len(GTPTunnel.GTPTEID.Value))
	}
	teid := binary.BigEndian.Uint32(GTPTunnel.GTPTEID.Value)

	for _, dataPath := range ctx.Tunnel.DataPathPool {
		if dataPath.Activated {
			ANUPF := dataPath.FirstDPNode
			for _, DLPDR := range ANUPF.DownLinkTunnel.PDR {
				DLPDR.FAR.ForwardingParameters.OuterHeaderCreation = new(OuterHeaderCreation)
				dlOuterHeaderCreation := DLPDR.FAR.ForwardingParameters.OuterHeaderCreation
				dlOuterHeaderCreation.OuterHeaderCreationDescription = OuterHeaderCreationGtpUUdpIpv4
				dlOuterHeaderCreation.Teid = teid
				dlOuterHeaderCreation.Ipv4Address = GTPTunnel.TransportLayerAddress.Value.Bytes
				DLPDR.FAR.State = RULE_UPDATE
			}
		}
	}

	return nil
}
