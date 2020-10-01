package cmd

import (
	"fmt"
	"io"
	"ksniff/kube"
	"ksniff/pkg/config"
	"ksniff/pkg/service/sniffer"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/mitchellh/go-homedir"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"

	_ "k8s.io/client-go/plugin/pkg/client/auth/azure"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	_ "k8s.io/client-go/plugin/pkg/client/auth/oidc"
)

var (
	ksniffExample = "kubectl sniff hello-minikube-7c77b68cff-qbvsd -c hello-minikube"
)

const minimumNumberOfArguments = 1
const tcpdumpBinaryName = "static-tcpdump"
const tcpdumpRemotePath = "/tmp/static-tcpdump"

var tcpdumpLocalBinaryPathLookupList []string

type Ksniff struct {
	configFlags      *genericclioptions.ConfigFlags
	resultingContext *api.Context
	clientset        *kubernetes.Clientset
	restConfig       *rest.Config
	rawConfig        api.Config
	settings         *config.KsniffSettings
	snifferService   sniffer.SnifferService
}

//PodInfo to collect pod data and configure the capture
type PodInfo struct {
	Name string `json:"name"`
	//Node          string `json:"node"`
}

func NewKsniff(settings *config.KsniffSettings) *Ksniff {
	return &Ksniff{settings: settings, configFlags: genericclioptions.NewConfigFlags(true)}
}

func NewCmdSniff(streams genericclioptions.IOStreams) *cobra.Command {
	ksniffSettings := config.NewKsniffSettings(streams)

	ksniff := NewKsniff(ksniffSettings)

	cmd := &cobra.Command{
		Use:          "sniff pod [-n namespace] [-c container] [-f filter] [-o output-file] [-l local-tcpdump-path] [-r remote-tcpdump-path]",
		Short:        "Perform network sniffing on a container running in a kubernetes cluster.",
		Example:      ksniffExample,
		SilenceUsage: true,
		RunE: func(c *cobra.Command, args []string) error {

			if err := ksniff.Complete(c, args); err != nil {
				return err
			}

			if err := ksniff.Validate(); err != nil {
				return err
			}

			// run the capture on multiple pods otherwise on a single pod
			if len(ksniff.settings.PodSlice) > 0 {
				for _, pod := range ksniff.settings.PodSlice {
					if err := ksniff.MultiRun(pod); err != nil {
						return err
					}
				}
			} else {
				if err := ksniff.Run(); err != nil {
					return err
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&ksniffSettings.UserSpecifiedLabel, "label", "", "", "label (optional)")
	_ = viper.BindEnv("label", "KUBECTL_PLUGINS_LABEL")
	_ = viper.BindPFlag("label", cmd.Flags().Lookup("label"))

	cmd.Flags().StringVarP(&ksniffSettings.PodFlag, "pod", "", "", "pod (optional)")
	_ = viper.BindEnv("pod", "KUBECTL_PLUGINS_POD")
	_ = viper.BindPFlag("pod", cmd.Flags().Lookup("pod"))

	cmd.Flags().StringVarP(&ksniffSettings.UserSpecifiedNamespace, "namespace", "n", "default", "namespace (optional)")
	_ = viper.BindEnv("namespace", "KUBECTL_PLUGINS_CURRENT_NAMESPACE")
	_ = viper.BindPFlag("namespace", cmd.Flags().Lookup("namespace"))

	cmd.Flags().StringVarP(&ksniffSettings.UserSpecifiedInterface, "interface", "i", "any", "pod interface to packet capture (optional)")
	_ = viper.BindEnv("interface", "KUBECTL_PLUGINS_LOCAL_FLAG_INTERFACE")
	_ = viper.BindPFlag("interface", cmd.Flags().Lookup("interface"))

	cmd.Flags().StringVarP(&ksniffSettings.UserSpecifiedContainer, "container", "c", "", "container (optional)")
	_ = viper.BindEnv("container", "KUBECTL_PLUGINS_LOCAL_FLAG_CONTAINER")
	_ = viper.BindPFlag("container", cmd.Flags().Lookup("container"))

	cmd.Flags().StringVarP(&ksniffSettings.UserSpecifiedFilter, "filter", "f", "", "tcpdump filter (optional)")
	_ = viper.BindEnv("filter", "KUBECTL_PLUGINS_LOCAL_FLAG_FILTER")
	_ = viper.BindPFlag("filter", cmd.Flags().Lookup("filter"))

	cmd.Flags().StringVarP(&ksniffSettings.UserSpecifiedOutputFile, "output-file", "o", "",
		"output file path, tcpdump output will be redirect to this file instead of wireshark (optional) ('-' stdout)")
	_ = viper.BindEnv("output-file", "KUBECTL_PLUGINS_LOCAL_FLAG_OUTPUT_FILE")
	_ = viper.BindPFlag("output-file", cmd.Flags().Lookup("output-file"))

	cmd.Flags().StringVarP(&ksniffSettings.UserSpecifiedLocalTcpdumpPath, "local-tcpdump-path", "l", "",
		"local static tcpdump binary path (optional)")
	_ = viper.BindEnv("local-tcpdump-path", "KUBECTL_PLUGINS_LOCAL_FLAG_LOCAL_TCPDUMP_PATH")
	_ = viper.BindPFlag("local-tcpdump-path", cmd.Flags().Lookup("local-tcpdump-path"))

	cmd.Flags().StringVarP(&ksniffSettings.UserSpecifiedRemoteTcpdumpPath, "remote-tcpdump-path", "r", tcpdumpRemotePath,
		"remote static tcpdump binary path (optional)")
	_ = viper.BindEnv("remote-tcpdump-path", "KUBECTL_PLUGINS_LOCAL_FLAG_REMOTE_TCPDUMP_PATH")
	_ = viper.BindPFlag("remote-tcpdump-path", cmd.Flags().Lookup("remote-tcpdump-path"))

	cmd.Flags().BoolVarP(&ksniffSettings.UserSpecifiedVerboseMode, "verbose", "v", false,
		"if specified, ksniff output will include debug information (optional)")
	_ = viper.BindEnv("verbose", "KUBECTL_PLUGINS_LOCAL_FLAG_VERBOSE")
	_ = viper.BindPFlag("verbose", cmd.Flags().Lookup("verbose"))

	cmd.Flags().BoolVarP(&ksniffSettings.UserSpecifiedPrivilegedMode, "privileged", "p", false,
		"if specified, ksniff will deploy another pod that have privileges to attach target pod network namespace")
	_ = viper.BindEnv("privileged", "KUBECTL_PLUGINS_LOCAL_FLAG_PRIVILEGED")
	_ = viper.BindPFlag("privileged", cmd.Flags().Lookup("privileged"))

	cmd.Flags().StringVarP(&ksniffSettings.Image, "image", "", "docker",
		"the privileged container image (optional)")
	_ = viper.BindEnv("image", "KUBECTL_PLUGINS_LOCAL_FLAG_IMAGE")
	_ = viper.BindPFlag("image", cmd.Flags().Lookup("image"))

	cmd.Flags().StringVarP(&ksniffSettings.UserSpecifiedKubeContext, "context", "x", "",
		"kubectl context to work on (optional)")
	_ = viper.BindEnv("context", "KUBECTL_PLUGINS_CURRENT_CONTEXT")
	_ = viper.BindPFlag("context", cmd.Flags().Lookup("context"))

	return cmd
}

//fetchPods fetches the pods that match the label
func (o *Ksniff) fetchPods() error {

	//fetch pods
	pods, err := o.clientset.CoreV1().Pods(o.settings.UserSpecifiedNamespace).List(v1.ListOptions{LabelSelector: o.settings.UserSpecifiedLabel})
	if err != nil {
		return err
	}

	if len(pods.Items) != 0 {
		for _, pod := range pods.Items {
			//targetPods = append(targetPods, pod.Name)
			o.settings.PodSlice = append(o.settings.PodSlice, pod.Name)
		}
	} else {
		return errors.New("no containers in specified pod")
	}

	return nil
}

func (o *Ksniff) Complete(cmd *cobra.Command, args []string) error {

	o.settings.PodFlag = viper.GetString("pod")
	o.settings.UserSpecifiedLabel = viper.GetString("label")
	o.settings.UserSpecifiedNamespace = viper.GetString("namespace")
	o.settings.UserSpecifiedContainer = viper.GetString("container")
	o.settings.UserSpecifiedInterface = viper.GetString("interface")
	o.settings.UserSpecifiedFilter = viper.GetString("filter")
	o.settings.UserSpecifiedOutputFile = viper.GetString("output-file")
	o.settings.UserSpecifiedLocalTcpdumpPath = viper.GetString("local-tcpdump-path")
	o.settings.UserSpecifiedRemoteTcpdumpPath = viper.GetString("remote-tcpdump-path")
	o.settings.UserSpecifiedVerboseMode = viper.GetBool("verbose")
	o.settings.UserSpecifiedPrivilegedMode = viper.GetBool("privileged")
	o.settings.UserSpecifiedKubeContext = viper.GetString("context")

	var err error

	if o.settings.UserSpecifiedVerboseMode {
		log.Info("running in verbose mode")
		log.SetLevel(log.DebugLevel)
	}

	tcpdumpLocalBinaryPathLookupList, err = o.buildTcpdumpBinaryPathLookupList()
	if err != nil {
		return err
	}

	o.rawConfig, err = o.configFlags.ToRawKubeConfigLoader().RawConfig()
	if err != nil {
		return err
	}

	var currentContext *api.Context
	var exists bool

	if o.settings.UserSpecifiedKubeContext != "" {
		currentContext, exists = o.rawConfig.Contexts[o.settings.UserSpecifiedKubeContext]
	} else {
		currentContext, exists = o.rawConfig.Contexts[o.rawConfig.CurrentContext]
	}

	if !exists {
		return errors.New("context doesn't exist")
	}

	o.restConfig, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: o.configFlags.ToRawKubeConfigLoader().ConfigAccess().GetDefaultFilename()},
		&clientcmd.ConfigOverrides{
			CurrentContext: o.settings.UserSpecifiedKubeContext,
		}).ClientConfig()

	if err != nil {
		return err
	}

	o.restConfig.Timeout = 30 * time.Second

	o.clientset, err = kubernetes.NewForConfig(o.restConfig)
	if err != nil {
		return err
	}

	o.resultingContext = currentContext.DeepCopy()
	o.resultingContext.Namespace = o.settings.UserSpecifiedNamespace
	kubernetesApiService := kube.NewKubernetesApiService(o.clientset, o.restConfig, o.settings.UserSpecifiedNamespace)

	if o.settings.UserSpecifiedPrivilegedMode {
		log.Info("sniffing method: privileged pod")
		o.snifferService = sniffer.NewPrivilegedPodRemoteSniffingService(o.settings, kubernetesApiService)
	} else {
		log.Info("sniffing method: upload static tcpdump")
		o.snifferService = sniffer.NewUploadTcpdumpRemoteSniffingService(o.settings, kubernetesApiService)
	}

	//search pods by label
	if o.settings.UserSpecifiedLabel != "" {
		log.Info("searching for pods with a label")
		if err := o.fetchPods(); err != nil {
			return err
		}
	}

	return nil
}

func (o *Ksniff) buildTcpdumpBinaryPathLookupList() ([]string, error) {
	userHomeDir, err := homedir.Dir()
	if err != nil {
		return nil, err
	}

	ksniffBinaryPath, err := filepath.EvalSymlinks(os.Args[0])
	if err != nil {
		return nil, err
	}

	ksniffBinaryDir := filepath.Dir(ksniffBinaryPath)
	ksniffBinaryPath = filepath.Join(ksniffBinaryDir, tcpdumpBinaryName)

	kubeKsniffPluginFolder := filepath.Join(userHomeDir, filepath.FromSlash("/.kube/plugin/sniff/"), tcpdumpBinaryName)

	return append([]string{o.settings.UserSpecifiedLocalTcpdumpPath, ksniffBinaryPath},
		filepath.Join("/usr/local/bin/", tcpdumpBinaryName), kubeKsniffPluginFolder), nil
}

//ValidatePods validates a provided pod
func (o *Ksniff) ValidatePods(podName string, namespace string) error {

	log.Print(podName, namespace)
	pod, err := o.clientset.CoreV1().Pods(namespace).Get(podName, v1.GetOptions{})
	if err != nil {
		return err
	}

	if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
		return errors.Errorf("cannot sniff on a container in a completed pod; current phase is %s", pod.Status.Phase)
	}

	o.settings.DetectedPodNodeName = pod.Spec.NodeName

	log.Debugf("pod '%s' status: '%s'", o.settings.UserSpecifiedPodName, pod.Status.Phase)

	if len(pod.Spec.Containers) < 1 {
		return errors.New("no containers in specified pod")
	}

	if o.settings.UserSpecifiedContainer == "" {
		log.Info("no container specified, taking first container we found in pod.")
		o.settings.UserSpecifiedContainer = pod.Spec.Containers[0].Name
		log.Infof("selected container: '%s'", o.settings.UserSpecifiedContainer)
	}

	var containerFoundInPod = false
	for _, containerStatus := range pod.Status.ContainerStatuses {
		if o.settings.UserSpecifiedContainer == containerStatus.Name {
			o.settings.DetectedContainerId = strings.TrimPrefix(containerStatus.ContainerID, "docker://")
			containerFoundInPod = true
			break
		}
	}

	if !containerFoundInPod {
		return errors.Errorf("couldn't find container: '%s' in pod: '%s'", o.settings.UserSpecifiedContainer, o.settings.UserSpecifiedPodName)
	}

	return nil
}

func (o *Ksniff) Validate() error {
	if len(o.rawConfig.CurrentContext) == 0 {
		return errors.New("context doesn't exist")
	}

	if o.settings.UserSpecifiedNamespace == "" {
		return errors.New("namespace value is empty should be custom or default")
	}

	var err error

	o.settings.UserSpecifiedLocalTcpdumpPath, err = findLocalTcpdumpBinaryPath()
	if err != nil {
		return err
	}

	log.Infof("using tcpdump path at: '%s'", o.settings.UserSpecifiedLocalTcpdumpPath)

	if len(o.settings.PodSlice) != 0 {
		log.Info("capturing on all pods")
		for _, pod := range o.settings.PodSlice {
			if err := o.ValidatePods(pod, o.settings.UserSpecifiedNamespace); err != nil {
				return err
			}
		}

	} else {
		log.Info("capturing on a single pod")
		if err := o.ValidatePods(o.settings.PodFlag, o.settings.UserSpecifiedNamespace); err != nil {
			//return fmt.Errorf("error searching for individual pod, %v", err)
			return errors.Errorf("ValidatePods: %v", err)
		}
	}
	// pod, err := o.clientset.CoreV1().Pods(o.settings.UserSpecifiedNamespace).Get(o.settings.UserSpecifiedPodName, v1.GetOptions{})
	// if err != nil {
	// 	return err
	// }

	// if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
	// 	return errors.Errorf("cannot sniff on a container in a completed pod; current phase is %s", pod.Status.Phase)
	// }

	// o.settings.DetectedPodNodeName = pod.Spec.NodeName

	// log.Debugf("pod '%s' status: '%s'", o.settings.UserSpecifiedPodName, pod.Status.Phase)

	// if len(pod.Spec.Containers) < 1 {
	// 	return errors.New("no containers in specified pod")
	// }

	// if o.settings.UserSpecifiedContainer == "" {
	// 	log.Info("no container specified, taking first container we found in pod.")
	// 	o.settings.UserSpecifiedContainer = pod.Spec.Containers[0].Name
	// 	log.Infof("selected container: '%s'", o.settings.UserSpecifiedContainer)
	// }

	// var containerFoundInPod = false
	// for _, containerStatus := range pod.Status.ContainerStatuses {
	// 	if o.settings.UserSpecifiedContainer == containerStatus.Name {
	// 		o.settings.DetectedContainerId = strings.TrimPrefix(containerStatus.ContainerID, "docker://")
	// 		containerFoundInPod = true
	// 		break
	// 	}
	// }

	// if !containerFoundInPod {
	// 	return errors.Errorf("couldn't find container: '%s' in pod: '%s'", o.settings.UserSpecifiedContainer, o.settings.UserSpecifiedPodName)
	// }

	return nil
}

func findLocalTcpdumpBinaryPath() (string, error) {
	log.Debugf("searching for tcpdump binary using lookup list: '%v'", tcpdumpLocalBinaryPathLookupList)

	for _, possibleTcpdumpPath := range tcpdumpLocalBinaryPathLookupList {
		if _, err := os.Stat(possibleTcpdumpPath); err == nil {
			log.Debugf("tcpdump binary found at: '%s'", possibleTcpdumpPath)

			return possibleTcpdumpPath, nil
		}

		log.Debugf("tcpdump binary was not found at: '%s'", possibleTcpdumpPath)
	}

	return "", errors.Errorf("couldn't find static tcpdump binary on any of: '%v'", tcpdumpLocalBinaryPathLookupList)
}

func (o *Ksniff) Run() error {
	log.Infof("sniffing on pod: '%s' [namespace: '%s', container: '%s', filter: '%s', interface: '%s']",
		o.settings.UserSpecifiedPodName, o.settings.UserSpecifiedNamespace, o.settings.UserSpecifiedContainer, o.settings.UserSpecifiedFilter, o.settings.UserSpecifiedInterface)

	err := o.snifferService.Setup()
	if err != nil {
		return err
	}

	defer func() {
		log.Info("starting sniffer cleanup")

		err := o.snifferService.Cleanup()
		if err != nil {
			log.WithError(err).Error("failed to teardown sniffer, a manual teardown is required.")
			return
		}

		log.Info("sniffer cleanup completed successfully")
	}()

	if o.settings.UserSpecifiedOutputFile != "" {
		log.Infof("output file option specified, storing output in: '%s'", o.settings.UserSpecifiedOutputFile)

		var err error
		var fileWriter io.Writer

		if o.settings.UserSpecifiedOutputFile == "-" {
			fileWriter = os.Stdout
		} else {
			fileWriter, err = os.Create(o.settings.UserSpecifiedOutputFile)
			if err != nil {
				return err
			}
		}

		err = o.snifferService.Start(fileWriter)
		if err != nil {
			return err
		}

	} else {
		log.Info("spawning wireshark!")

		title := fmt.Sprintf("gui.window_title:%s/%s/%s", o.settings.UserSpecifiedNamespace, o.settings.UserSpecifiedPodName, o.settings.UserSpecifiedContainer)
		cmd := exec.Command("wireshark", "-k", "-i", "-", "-o", title)

		stdinWriter, err := cmd.StdinPipe()
		if err != nil {
			return err
		}

		go func() {
			err := o.snifferService.Start(stdinWriter)
			if err != nil {
				log.WithError(err).Errorf("failed to start remote sniffing, stopping wireshark")
				_ = cmd.Process.Kill()
			}
		}()

		err = cmd.Run()
		if err != nil {
			return err
		}
	}

	return nil
}

//MultiRun captures on multiple pods
func (o *Ksniff) MultiRun(podName string) error {
	log.Infof("sniffing on pod: '%s' [namespace: '%s', container: '%s', filter: '%s', interface: '%s']",
		podName, o.settings.UserSpecifiedNamespace, o.settings.UserSpecifiedContainer, o.settings.UserSpecifiedFilter, o.settings.UserSpecifiedInterface)

	err := o.snifferService.Setup()
	if err != nil {
		return err
	}

	defer func() {
		log.Info("starting sniffer cleanup")

		err := o.snifferService.Cleanup()
		if err != nil {
			log.WithError(err).Error("failed to teardown sniffer, a manual teardown is required.")
			return
		}

		log.Info("sniffer cleanup completed successfully")
	}()

	//create output file name
	o.settings.UserSpecifiedOutputFile = podName + ".pcap"
	//if o.settings.UserSpecifiedOutputFile != "" {
	log.Infof("output file option specified, storing output in: '%s'", o.settings.UserSpecifiedOutputFile)

	//var err error
	var fileWriter io.Writer

	if o.settings.UserSpecifiedOutputFile == "-" {
		fileWriter = os.Stdout
	} else {
		fileWriter, err = os.Create(o.settings.UserSpecifiedOutputFile)
		if err != nil {
			return err
		}
	}

	err = o.snifferService.Start(fileWriter)
	if err != nil {
		return err
	}

	//}
	// else {
	// 	log.Info("spawning wireshark!")

	// 	title := fmt.Sprintf("gui.window_title:%s/%s/%s", o.settings.UserSpecifiedNamespace, o.settings.UserSpecifiedPodName, o.settings.UserSpecifiedContainer)
	// 	cmd := exec.Command("wireshark", "-k", "-i", "-", "-o", title)

	// 	stdinWriter, err := cmd.StdinPipe()
	// 	if err != nil {
	// 		return err
	// 	}

	// 	go func() {
	// 		err := o.snifferService.Start(stdinWriter)
	// 		if err != nil {
	// 			log.WithError(err).Errorf("failed to start remote sniffing, stopping wireshark")
	// 			_ = cmd.Process.Kill()
	// 		}
	// 	}()

	// 	err = cmd.Run()
	// 	if err != nil {
	// 		return err
	// 	}
	// }

	return nil
}
