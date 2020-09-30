package config

import (
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

type KsniffSettings struct {
	PodFlag                        string
	UserSpecifiedLabel             string
	UserSpecifiedPodName           string
	UserSpecifiedInterface         string
	UserSpecifiedFilter            string
	UserSpecifiedContainer         string
	UserSpecifiedNamespace         string
	UserSpecifiedOutputFile        string
	UserSpecifiedLocalTcpdumpPath  string
	UserSpecifiedRemoteTcpdumpPath string
	UserSpecifiedVerboseMode       bool
	UserSpecifiedPrivilegedMode    bool
	DetectedPodNodeName            string
	DetectedContainerId            string
	Image                          string
	UserSpecifiedKubeContext       string
	PodSlice                       []string
}

func NewKsniffSettings(streams genericclioptions.IOStreams) *KsniffSettings {
	return &KsniffSettings{}
}
