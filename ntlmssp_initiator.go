package smb2

import (
	"encoding/asn1"
	"errors"
	"github.com/LeakIX/go-smb2/lib/spnego"
	"github.com/LeakIX/ntlmssp"
)

// NTLMInitiator implements session-setup through NTLMv2.
type NTLMSSPInitiator struct {
	NTLMSSPClient *ntlmssp.Client
	seqNum        uint32
	ntlmInfoMap   *NTLMSSPInfoMap
}

type NTLMSSPInfoMap struct {
	NbComputerName  string
	NbDomainName    string
	DnsComputerName string
	DnsDomainName   string
	DnsTreeName     string
	// Flags           uint32
	// Timestamp       time.Time
	// SingleHost
	// TargetName string
	// ChannelBindings
}

func (i *NTLMSSPInitiator) oid() asn1.ObjectIdentifier {
	return spnego.NlmpOid
}

func (i *NTLMSSPInitiator) GetInfoMap() *NTLMSSPInfoMap {
	return i.infoMap()
}

func (i *NTLMSSPInitiator) initSecContext() (_ []byte, err error) {
	if err != nil {
		return nil, err
	}
	nmsg, err := i.NTLMSSPClient.Authenticate(nil, nil)
	if err != nil {
		return nil, err
	}
	return nmsg, nil
}

func (i *NTLMSSPInitiator) acceptSecContext(sc []byte) ([]byte, error) {
	amsg, err := i.NTLMSSPClient.Authenticate(sc, nil)
	if err != nil {
		return nil, err
	}

	i.ntlmInfoMap = &NTLMSSPInfoMap{
		NbComputerName:  "",
		NbDomainName:    "",
		DnsComputerName: "",
		DnsDomainName:   "",
		DnsTreeName:     "",
	}
	if NbComputerName, found := i.NTLMSSPClient.SessionDetails().TargetInfo.GetString(ntlmssp.MsvAvNbComputerName); found {
		i.ntlmInfoMap.NbComputerName = NbComputerName
	}
	if NbDomainName, found := i.NTLMSSPClient.SessionDetails().TargetInfo.GetString(ntlmssp.MsvAvNbDomainName); found {
		i.ntlmInfoMap.NbDomainName = NbDomainName
	}
	if DnsComputerName, found := i.NTLMSSPClient.SessionDetails().TargetInfo.GetString(ntlmssp.MsvAvDNSComputerName); found {
		i.ntlmInfoMap.DnsComputerName = DnsComputerName
	}
	if DnsDomainName, found := i.NTLMSSPClient.SessionDetails().TargetInfo.GetString(ntlmssp.MsvAvDNSDomainName); found {
		i.ntlmInfoMap.DnsDomainName = DnsDomainName
	}
	if DnsTreeName, found := i.NTLMSSPClient.SessionDetails().TargetInfo.GetString(ntlmssp.MsvAvDNSTreeName); found {
		i.ntlmInfoMap.DnsTreeName = DnsTreeName
	}
	if i.NTLMSSPClient.SecuritySession() == nil {
		return nil, errors.New("failed to establish secure session")
	}
	return amsg, nil
}

func (i *NTLMSSPInitiator) sum(bs []byte) []byte {
	mac, _ := i.NTLMSSPClient.SecuritySession().Mac(bs)
	return mac
}

func (i *NTLMSSPInitiator) sessionKey() []byte {
	return i.NTLMSSPClient.SessionDetails().ExportedSessionKey
}

func (i *NTLMSSPInitiator) infoMap() *NTLMSSPInfoMap {
	return i.ntlmInfoMap
}
