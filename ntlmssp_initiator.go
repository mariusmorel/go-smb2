package smb2

import (
	"encoding/asn1"
	"github.com/LeakIX/ntlmssp"
	"github.com/LeakIX/go-smb2/lib/spnego"
)

// NTLMInitiator implements session-setup through NTLMv2.
// It doesn't support NTLMv1. You can use Hash instead of Password.
type NTLMSSPInitiator struct {
	User        string
	Password    string
	Hash        []byte
	Domain      string
	Workstation string
	TargetSPN   string
	ntlm        *ntlmssp.Client
	seqNum      uint32
	ntlmInfoMap *NTLMSSPInfoMap
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
	i.ntlm, err = ntlmssp.NewClient(ntlmssp.SetCompatibilityLevel(1), ntlmssp.SetUserInfo(i.User, i.Password), ntlmssp.SetDomain("NT AUTHORITY"))
	if err != nil {
		return nil, err
	}
	nmsg, err := i.ntlm.Authenticate(nil, nil)
	if err != nil {
		return nil, err
	}
	return nmsg, nil
}

func (i *NTLMSSPInitiator) acceptSecContext(sc []byte) ([]byte, error) {
	amsg, err := i.ntlm.Authenticate(sc, nil)
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
	if NbComputerName, found := i.ntlm.SessionDetails().TargetInfo.Get(ntlmssp.MsvAvNbComputerName); found {
		i.ntlmInfoMap.NbComputerName = string(NbComputerName)
	}
	if NbDomainName, found := i.ntlm.SessionDetails().TargetInfo.Get(ntlmssp.MsvAvNbDomainName); found {
		i.ntlmInfoMap.NbDomainName = string(NbDomainName)
	}
	if DnsComputerName, found := i.ntlm.SessionDetails().TargetInfo.Get(ntlmssp.MsvAvDNSComputerName); found {
		i.ntlmInfoMap.DnsComputerName = string(DnsComputerName)
	}
	if DnsDomainName, found := i.ntlm.SessionDetails().TargetInfo.Get(ntlmssp.MsvAvDNSDomainName); found {
		i.ntlmInfoMap.DnsDomainName = string(DnsDomainName)
	}
	if DnsTreeName, found := i.ntlm.SessionDetails().TargetInfo.Get(ntlmssp.MsvAvDNSTreeName); found {
		i.ntlmInfoMap.DnsTreeName = string(DnsTreeName)
	}
	return amsg, nil
}

func (i *NTLMSSPInitiator) sum(bs []byte) []byte {
	return nil
}

func (i *NTLMSSPInitiator) sessionKey() []byte {
	return i.ntlm.SessionDetails().ExportedSessionKey
}

func (i *NTLMSSPInitiator) infoMap() *NTLMSSPInfoMap {
	return i.ntlmInfoMap
}
