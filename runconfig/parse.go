package runconfig

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/docker/docker/opts"
	flag "github.com/docker/docker/pkg/mflag"
	"github.com/docker/docker/pkg/nat"
	"github.com/docker/docker/pkg/parsers"
	"github.com/docker/docker/pkg/units"
)

var (
	ErrConflictContainerNetworkAndLinks = fmt.Errorf("Conflicting options: --net=container can't be used with links. This would result in undefined behavior")
	ErrConflictNetworkAndDns            = fmt.Errorf("Conflicting options: --dns and the network mode (--net)")
	ErrConflictNetworkHostname          = fmt.Errorf("Conflicting options: -h and the network mode (--net)")
	ErrConflictHostNetworkAndLinks      = fmt.Errorf("Conflicting options: --net=host can't be used with links. This would result in undefined behavior")
	ErrConflictContainerNetworkAndMac   = fmt.Errorf("Conflicting options: --mac-address and the network mode (--net)")
	ErrConflictNetworkHosts             = fmt.Errorf("Conflicting options: --add-host and the network mode (--net)")
	ErrConflictNetworkPublishPorts      = fmt.Errorf("Conflicting options: -p, -P, --publish-all, --publish and the network mode (--net)")
	ErrConflictNetworkExposePorts       = fmt.Errorf("Conflicting options: --expose and the network mode (--expose)")
)

// validateNM is the set of fields passed to validateNetMode()
type validateNM struct {
	netMode        NetworkMode
	flHostname     *string
	flLinks        opts.ListOpts
	flDns          opts.ListOpts
	flExtraHosts   opts.ListOpts
	flMacAddress   *string
	flPublish      opts.ListOpts
	flPublishAll   *bool
	flExpose       opts.ListOpts
	flVolumeDriver string
}

var rateSuffix = map[string]int64{
	"bit":   1,
	"Kibit": 1024,
	"kbit":  1000,
	"mibit": 1024 * 1024,
	"mbit":  1000000,
	"gibit": 1024 * 1024 * 1024,
	"gbit":  1000000000,
	"tibit": 1024 * 1024 * 1024 * 1024,
	"tbit":  1000000000000,
	"Bps":   8,
	"KiBps": 8 * 1024,
	"KBps":  8000,
	"MiBps": 8 * 1024 * 1024,
	"MBps":  8000000,
	"GiBps": 8 * 1024 * 1024 * 1024,
	"GBps":  8000000000,
	"TiBps": 8 * 1024 * 1024 * 1024 * 1024,
	"TBps":  8000000000000,
}

func parseRate(rateStr string) (int64, error) {
	var i int
	var rate int64 = 0
	var rateUnits string
	for i = 0; i < len(rateStr); i++ {
		var v int64
		d := rateStr[i]
		if d <= '9' && d >= '0' {
			v = int64(d - '0')
			rate *= 10
			rate1 := rate + v
			if rate1 < rate || rate1 > math.MaxUint32 {
				goto Error
			}
			rate = rate1
		} else {
			break
		}
	}

	if i == 0 || i == len(rateStr) {
		goto Error
	}

	rateUnits = rateStr[i:]

	if mul, ok := rateSuffix[rateUnits]; ok {
		rate1 := rate * mul
		if rate1 < rate || rate1 > math.MaxUint32 {
			goto Error
		}
		rate = rate1 / 8
		if rate == 0 {
			goto Error
		}
	} else {
		goto Error
	}

	return rate, nil
Error:
	return -1, fmt.Errorf("invalid rate: '%s', traffic rate should be between 0 and %d", rateStr, math.MaxUint32)
}

func Parse(cmd *flag.FlagSet, args []string) (*Config, *HostConfig, *flag.FlagSet, error) {
	var (
		// FIXME: use utils.ListOpts for attach and volumes?
		flAttach  = opts.NewListOpts(opts.ValidateAttach)
		flVolumes = opts.NewListOpts(opts.ValidatePath)
		flLinks   = opts.NewListOpts(opts.ValidateLink)
		flEnv     = opts.NewListOpts(opts.ValidateEnv)
		flLabels  = opts.NewListOpts(opts.ValidateEnv)
		flDevices = opts.NewListOpts(opts.ValidateDevice)

		flUlimits = opts.NewUlimitOpt(nil)

		flPublish     = opts.NewListOpts(nil)
		flExpose      = opts.NewListOpts(nil)
		flDns         = opts.NewListOpts(opts.ValidateIPAddress)
		flDnsSearch   = opts.NewListOpts(opts.ValidateDNSSearch)
		flExtraHosts  = opts.NewListOpts(opts.ValidateExtraHost)
		flVolumesFrom = opts.NewListOpts(nil)
		flLxcOpts     = opts.NewListOpts(nil)
		flEnvFile     = opts.NewListOpts(nil)
		flCapAdd      = opts.NewListOpts(nil)
		flCapDrop     = opts.NewListOpts(nil)
		flGroupAdd    = opts.NewListOpts(nil)
		flSecurityOpt = opts.NewListOpts(nil)
		flLabelsFile  = opts.NewListOpts(nil)
		flLoggingOpts = opts.NewListOpts(nil)

		flBlkioThrottleReadBpsDevice   = opts.NewListOpts(opts.ValidateDeviceThrottle)
		flBlkioThrottleWriteBpsDevice  = opts.NewListOpts(opts.ValidateDeviceThrottle)
		flBlkioThrottleReadIOpsDevice  = opts.NewListOpts(opts.ValidateDeviceThrottle)
		flBlkioThrottleWriteIOpsDevice = opts.NewListOpts(opts.ValidateDeviceThrottle)

		flNetwork         = cmd.Bool([]string{"#n", "#-networking"}, true, "Enable networking for this container")
		flPrivileged      = cmd.Bool([]string{"#privileged", "-privileged"}, false, "Give extended privileges to this container")
		flPidMode         = cmd.String([]string{"-pid"}, "", "PID namespace to use")
		flUTSMode         = cmd.String([]string{"-uts"}, "", "UTS namespace to use")
		flPublishAll      = cmd.Bool([]string{"P", "-publish-all"}, false, "Publish all exposed ports to random ports")
		flStdin           = cmd.Bool([]string{"i", "-interactive"}, false, "Keep STDIN open even if not attached")
		flTty             = cmd.Bool([]string{"t", "-tty"}, false, "Allocate a pseudo-TTY")
		flOomKillDisable  = cmd.Bool([]string{"-oom-kill-disable"}, false, "Disable OOM Killer")
		flContainerIDFile = cmd.String([]string{"#cidfile", "-cidfile"}, "", "Write the container ID to the file")
		flEntrypoint      = cmd.String([]string{"#entrypoint", "-entrypoint"}, "", "Overwrite the default ENTRYPOINT of the image")
		flFilesystemQuota = cmd.String([]string{"-filesystem-quota"}, "", "Filesystem space limit")
		flHostname        = cmd.String([]string{"h", "-hostname"}, "", "Container host name")
		flMemoryString    = cmd.String([]string{"m", "-memory"}, "", "Memory limit")
		flMemorySwap      = cmd.String([]string{"-memory-swap"}, "", "Total memory (memory + swap), '-1' to disable swap")
		flUser            = cmd.String([]string{"u", "-user"}, "", "Username or UID (format: <name|uid>[:<group|gid>])")
		flWorkingDir      = cmd.String([]string{"w", "-workdir"}, "", "Working directory inside the container")
		flCpuShares       = cmd.Int64([]string{"c", "-cpu-shares"}, 0, "CPU shares (relative weight)")
		flCpuPeriod       = cmd.Int64([]string{"-cpu-period"}, 0, "Limit CPU CFS (Completely Fair Scheduler) period")
		flCpuQuota        = cmd.Int64([]string{"-cpu-quota"}, 0, "Limit CPU CFS (Completely Fair Scheduler) quota")
		flCpusetCpus      = cmd.String([]string{"#-cpuset", "-cpuset-cpus"}, "", "CPUs in which to allow execution (0-3, 0,1)")
		flCpusetMems      = cmd.String([]string{"-cpuset-mems"}, "", "MEMs in which to allow execution (0-3, 0,1)")
		flBlkioWeight     = cmd.Int64([]string{"-blkio-weight"}, 0, "Block IO (relative weight), between 10 and 1000")
		flSwappiness      = cmd.Int64([]string{"-memory-swappiness"}, -1, "Tuning container memory swappiness (0 to 100)")
		flNetMode         = cmd.String([]string{"-net"}, "default", "Set the Network mode for the container")
		flMacAddress      = cmd.String([]string{"-mac-address"}, "", "Container MAC address (e.g. 92:d0:c6:0a:29:33)")
		flIpcMode         = cmd.String([]string{"-ipc"}, "", "IPC namespace to use")
		flRestartPolicy   = cmd.String([]string{"-restart"}, "no", "Restart policy to apply when a container exits")
		flReadonlyRootfs  = cmd.Bool([]string{"-read-only"}, false, "Mount the container's root filesystem as read only")
		flLoggingDriver   = cmd.String([]string{"-log-driver"}, "", "Logging driver for container")
		flCgroupParent    = cmd.String([]string{"-cgroup-parent"}, "", "Optional parent cgroup for the container")
		flVolumeDriver    = cmd.String([]string{"-volume-driver"}, "", "Optional volume driver for the container")
		flTcRate          = cmd.String([]string{"-tc-rate"}, "", "Traffic control rate allocated")
		flTcCeil          = cmd.String([]string{"-tc-ceil"}, "", "Traffic control upper rate")
		flTcBuffer        = cmd.String([]string{"-tc-buffer"}, "", "Traffic control max bytes burst which can be accumulated during idle period")
		flTcCbuffer       = cmd.String([]string{"-tc-cbuffer"}, "", "Traffic control max bytes burst for ceil which can be accumulated during idle period")
	)

	cmd.Var(&flAttach, []string{"a", "-attach"}, "Attach to STDIN, STDOUT or STDERR")
	cmd.Var(&flBlkioThrottleReadBpsDevice, []string{"-blkio-throttle-read-bps-device"}, "Constrict read bps for blk device")
	cmd.Var(&flBlkioThrottleWriteBpsDevice, []string{"-blkio-throttle-write-bps-device"}, "Constrict write bps for blk device")
	cmd.Var(&flBlkioThrottleReadIOpsDevice, []string{"-blkio-throttle-read-iops-device"}, "Constrict read iops for blk device")
	cmd.Var(&flBlkioThrottleWriteIOpsDevice, []string{"-blkio-throttle-write-iops-device"}, "Constrict write iops for blk device")
	cmd.Var(&flVolumes, []string{"v", "-volume"}, "Bind mount a volume")
	cmd.Var(&flLinks, []string{"#link", "-link"}, "Add link to another container")
	cmd.Var(&flDevices, []string{"-device"}, "Add a host device to the container")
	cmd.Var(&flLabels, []string{"l", "-label"}, "Set meta data on a container")
	cmd.Var(&flLabelsFile, []string{"-label-file"}, "Read in a line delimited file of labels")
	cmd.Var(&flEnv, []string{"e", "-env"}, "Set environment variables")
	cmd.Var(&flEnvFile, []string{"-env-file"}, "Read in a file of environment variables")
	cmd.Var(&flPublish, []string{"p", "-publish"}, "Publish a container's port(s) to the host")
	cmd.Var(&flExpose, []string{"#expose", "-expose"}, "Expose a port or a range of ports")
	cmd.Var(&flDns, []string{"#dns", "-dns"}, "Set custom DNS servers")
	cmd.Var(&flDnsSearch, []string{"-dns-search"}, "Set custom DNS search domains")
	cmd.Var(&flExtraHosts, []string{"-add-host"}, "Add a custom host-to-IP mapping (host:ip)")
	cmd.Var(&flVolumesFrom, []string{"#volumes-from", "-volumes-from"}, "Mount volumes from the specified container(s)")
	cmd.Var(&flLxcOpts, []string{"#lxc-conf", "-lxc-conf"}, "Add custom lxc options")
	cmd.Var(&flCapAdd, []string{"-cap-add"}, "Add Linux capabilities")
	cmd.Var(&flCapDrop, []string{"-cap-drop"}, "Drop Linux capabilities")
	cmd.Var(&flGroupAdd, []string{"-group-add"}, "Add additional groups to join")
	cmd.Var(&flSecurityOpt, []string{"-security-opt"}, "Security Options")
	cmd.Var(flUlimits, []string{"-ulimit"}, "Ulimit options")
	cmd.Var(&flLoggingOpts, []string{"-log-opt"}, "Log driver options")

	expFlags := attachExperimentalFlags(cmd)

	cmd.Require(flag.Min, 1)

	if err := cmd.ParseFlags(args, true); err != nil {
		return nil, nil, cmd, err
	}

	var (
		attachStdin  = flAttach.Get("stdin")
		attachStdout = flAttach.Get("stdout")
		attachStderr = flAttach.Get("stderr")
	)

	netMode, err := parseNetMode(*flNetMode)
	if err != nil {
		return nil, nil, cmd, fmt.Errorf("--net: invalid net mode: %v", err)
	}

	vals := validateNM{
		netMode:      netMode,
		flHostname:   flHostname,
		flLinks:      flLinks,
		flDns:        flDns,
		flExtraHosts: flExtraHosts,
		flMacAddress: flMacAddress,
		flPublish:    flPublish,
		flPublishAll: flPublishAll,
		flExpose:     flExpose,
	}

	if err := validateNetMode(&vals); err != nil {
		return nil, nil, cmd, err
	}

	// Validate the input mac address
	if *flMacAddress != "" {
		if _, err := opts.ValidateMACAddress(*flMacAddress); err != nil {
			return nil, nil, cmd, fmt.Errorf("%s is not a valid mac address", *flMacAddress)
		}
	}
	if *flStdin {
		attachStdin = true
	}
	// If -a is not set attach to the output stdio
	if flAttach.Len() == 0 {
		attachStdout = true
		attachStderr = true
	}

	var flMemory int64
	if *flMemoryString != "" {
		parsedMemory, err := units.RAMInBytes(*flMemoryString)
		if err != nil {
			return nil, nil, cmd, err
		}
		flMemory = parsedMemory
	}

	var MemorySwap int64
	if *flMemorySwap != "" {
		if *flMemorySwap == "-1" {
			MemorySwap = -1
		} else {
			parsedMemorySwap, err := units.RAMInBytes(*flMemorySwap)
			if err != nil {
				return nil, nil, cmd, err
			}
			MemorySwap = parsedMemorySwap
		}
	}

	swappiness := *flSwappiness
	if swappiness != -1 && (swappiness < 0 || swappiness > 100) {
		return nil, nil, cmd, fmt.Errorf("Invalid value: %d. Valid memory swappiness range is 0-100", swappiness)
	}
	var filesystemQuota int64 = -1
	if *flFilesystemQuota != "" {
		var err error
		filesystemQuota, err = units.RAMInBytes(*flFilesystemQuota)
		if err != nil {
			return nil, nil, cmd, err
		}
	}

	var tcRate, tcCeil, tcBuffer, tcCbuffer int64 = -1, 0, 0, 0
	//var tc *TrafficControl = nil
	if *flTcRate != "" {
		var err error
		if tcRate, err = parseRate(*flTcRate); err != nil {
			return nil, nil, cmd, err
		}
		if *flTcCeil != "" {
			if tcCeil, err = parseRate(*flTcCeil); err != nil {
				return nil, nil, cmd, err
			}
		}
		if *flTcBuffer != "" {
			if tcBuffer, err = units.RAMInBytes(*flTcBuffer); err != nil {
				return nil, nil, cmd, err
			}
		}
		if *flTcCbuffer != "" {
			if tcCbuffer, err = units.RAMInBytes(*flTcCbuffer); err != nil {
				return nil, nil, cmd, err
			}
		}
		//	if tcRate != -1 {
		//		tc = &TrafficControl{
		//			Rate:    tcRate,
		//			Ceil:    tcCeil,
		//			Buffer:  tcBuffer,
		//			Cbuffer: tcCbuffer,
		//		}
		//	}
	} else {
		if *flTcCeil != "" || *flTcBuffer != "" || *flTcCbuffer != "" {
			return nil, nil, cmd, fmt.Errorf("Redundant traffic control options")
		}
	}

	var binds []string
	// add any bind targets to the list of container volumes
	for bind := range flVolumes.GetMap() {
		if arr := strings.Split(bind, ":"); len(arr) > 1 {
			if arr[1] == "/" {
				return nil, nil, cmd, fmt.Errorf("Invalid bind mount: destination can't be '/'")
			}
			// after creating the bind mount we want to delete it from the flVolumes values because
			// we do not want bind mounts being committed to image configs
			binds = append(binds, bind)
			flVolumes.Delete(bind)
		} else if bind == "/" {
			return nil, nil, cmd, fmt.Errorf("Invalid volume: path can't be '/'")
		}
	}

	var (
		parsedArgs = cmd.Args()
		runCmd     *Command
		entrypoint *Entrypoint
		image      = cmd.Arg(0)
	)
	if len(parsedArgs) > 1 {
		runCmd = NewCommand(parsedArgs[1:]...)
	}
	if *flEntrypoint != "" {
		entrypoint = NewEntrypoint(*flEntrypoint)
	}

	lc, err := parseKeyValueOpts(flLxcOpts)
	if err != nil {
		return nil, nil, cmd, err
	}
	lxcConf := NewLxcConfig(lc)

	var (
		domainname string
		hostname   = *flHostname
		parts      = strings.SplitN(hostname, ".", 2)
	)
	if len(parts) > 1 {
		hostname = parts[0]
		domainname = parts[1]
	}

	ports, portBindings, err := nat.ParsePortSpecs(flPublish.GetAll())
	if err != nil {
		return nil, nil, cmd, err
	}

	// Merge in exposed ports to the map of published ports
	for _, e := range flExpose.GetAll() {
		if strings.Contains(e, ":") {
			return nil, nil, cmd, fmt.Errorf("Invalid port format for --expose: %s", e)
		}
		//support two formats for expose, original format <portnum>/[<proto>] or <startport-endport>/[<proto>]
		proto, port := nat.SplitProtoPort(e)
		//parse the start and end port and create a sequence of ports to expose
		//if expose a port, the start and end port are the same
		start, end, err := parsers.ParsePortRange(port)
		if err != nil {
			return nil, nil, cmd, fmt.Errorf("Invalid range format for --expose: %s, error: %s", e, err)
		}
		for i := start; i <= end; i++ {
			p, err := nat.NewPort(proto, strconv.FormatUint(i, 10))
			if err != nil {
				return nil, nil, cmd, err
			}
			if _, exists := ports[p]; !exists {
				ports[p] = struct{}{}
			}
		}
	}

	// parse device mappings
	deviceMappings := []DeviceMapping{}
	for _, device := range flDevices.GetAll() {
		deviceMapping, err := ParseDevice(device)
		if err != nil {
			return nil, nil, cmd, err
		}
		deviceMappings = append(deviceMappings, deviceMapping)
	}

	// collect all the environment variables for the container
	envVariables, err := readKVStrings(flEnvFile.GetAll(), flEnv.GetAll())
	if err != nil {
		return nil, nil, cmd, err
	}

	// collect all the labels for the container
	labels, err := readKVStrings(flLabelsFile.GetAll(), flLabels.GetAll())
	if err != nil {
		return nil, nil, cmd, err
	}

	ipcMode := IpcMode(*flIpcMode)
	if !ipcMode.Valid() {
		return nil, nil, cmd, fmt.Errorf("--ipc: invalid IPC mode")
	}

	pidMode := PidMode(*flPidMode)
	if !pidMode.Valid() {
		return nil, nil, cmd, fmt.Errorf("--pid: invalid PID mode")
	}

	utsMode := UTSMode(*flUTSMode)
	if !utsMode.Valid() {
		return nil, nil, cmd, fmt.Errorf("--uts: invalid UTS mode")
	}

	restartPolicy, err := ParseRestartPolicy(*flRestartPolicy)
	if err != nil {
		return nil, nil, cmd, err
	}

	loggingOpts, err := parseLoggingOpts(*flLoggingDriver, flLoggingOpts.GetAll())
	if err != nil {
		return nil, nil, cmd, err
	}

	config := &Config{
		Hostname:        hostname,
		Domainname:      domainname,
		ExposedPorts:    ports,
		User:            *flUser,
		Tty:             *flTty,
		NetworkDisabled: !*flNetwork,
		OpenStdin:       *flStdin,
		AttachStdin:     attachStdin,
		AttachStdout:    attachStdout,
		AttachStderr:    attachStderr,
		Env:             envVariables,
		Cmd:             runCmd,
		Image:           image,
		Volumes:         flVolumes.GetMap(),
		MacAddress:      *flMacAddress,
		Entrypoint:      entrypoint,
		WorkingDir:      *flWorkingDir,
		Labels:          convertKVStringsToMap(labels),
		VolumeDriver:    *flVolumeDriver,
	}

	hostConfig := &HostConfig{
		Binds:                        binds,
		ContainerIDFile:              *flContainerIDFile,
		LxcConf:                      lxcConf,
		Memory:                       flMemory,
		MemorySwap:                   MemorySwap,
		CpuShares:                    *flCpuShares,
		CpuPeriod:                    *flCpuPeriod,
		CpusetCpus:                   *flCpusetCpus,
		CpusetMems:                   *flCpusetMems,
		CpuQuota:                     *flCpuQuota,
		BlkioWeight:                  *flBlkioWeight,
		BlkioThrottleReadBpsDevice:   flBlkioThrottleReadBpsDevice.GetAll(),
		BlkioThrottleWriteBpsDevice:  flBlkioThrottleWriteBpsDevice.GetAll(),
		BlkioThrottleReadIOpsDevice:  flBlkioThrottleReadIOpsDevice.GetAll(),
		BlkioThrottleWriteIOpsDevice: flBlkioThrottleWriteIOpsDevice.GetAll(),
		OomKillDisable:               *flOomKillDisable,
		MemorySwappiness:             flSwappiness,
		Privileged:                   *flPrivileged,
		PortBindings:                 portBindings,
		Links:                        flLinks.GetAll(),
		PublishAllPorts:              *flPublishAll,
		Dns:                          flDns.GetAll(),
		DnsSearch:                    flDnsSearch.GetAll(),
		ExtraHosts:                   flExtraHosts.GetAll(),
		FilesystemQuota:              filesystemQuota,
		VolumesFrom:                  flVolumesFrom.GetAll(),
		NetworkMode:                  netMode,
		IpcMode:                      ipcMode,
		PidMode:                      pidMode,
		UTSMode:                      utsMode,
		Devices:                      deviceMappings,
		CapAdd:                       NewCapList(flCapAdd.GetAll()),
		CapDrop:                      NewCapList(flCapDrop.GetAll()),
		GroupAdd:                     flGroupAdd.GetAll(),
		RestartPolicy:                restartPolicy,
		SecurityOpt:                  flSecurityOpt.GetAll(),
		ReadonlyRootfs:               *flReadonlyRootfs,
		Ulimits:                      flUlimits.GetList(),
		LogConfig:                    LogConfig{Type: *flLoggingDriver, Config: loggingOpts},
		CgroupParent:                 *flCgroupParent,
		//TrafficControl:               tc,
		TcRate:    tcRate,
		TcCeil:    tcCeil,
		TcBuffer:  tcBuffer,
		TcCbuffer: tcCbuffer,
	}

	applyExperimentalFlags(expFlags, config, hostConfig)

	// When allocating stdin in attached mode, close stdin at client disconnect
	if config.OpenStdin && config.AttachStdin {
		config.StdinOnce = true
	}
	return config, hostConfig, cmd, nil
}

// reads a file of line terminated key=value pairs and override that with override parameter
func readKVStrings(files []string, override []string) ([]string, error) {
	envVariables := []string{}
	for _, ef := range files {
		parsedVars, err := opts.ParseEnvFile(ef)
		if err != nil {
			return nil, err
		}
		envVariables = append(envVariables, parsedVars...)
	}
	// parse the '-e' and '--env' after, to allow override
	envVariables = append(envVariables, override...)

	return envVariables, nil
}

// converts ["key=value"] to {"key":"value"}
func convertKVStringsToMap(values []string) map[string]string {
	result := make(map[string]string, len(values))
	for _, value := range values {
		kv := strings.SplitN(value, "=", 2)
		if len(kv) == 1 {
			result[kv[0]] = ""
		} else {
			result[kv[0]] = kv[1]
		}
	}

	return result
}

func parseLoggingOpts(loggingDriver string, loggingOpts []string) (map[string]string, error) {
	loggingOptsMap := convertKVStringsToMap(loggingOpts)
	if loggingDriver == "none" && len(loggingOpts) > 0 {
		return map[string]string{}, fmt.Errorf("Invalid logging opts for driver %s", loggingDriver)
	}
	return loggingOptsMap, nil
}

// ParseRestartPolicy returns the parsed policy or an error indicating what is incorrect
func ParseRestartPolicy(policy string) (RestartPolicy, error) {
	p := RestartPolicy{}

	if policy == "" {
		return p, nil
	}

	var (
		parts = strings.Split(policy, ":")
		name  = parts[0]
	)

	p.Name = name
	switch name {
	case "always":
		if len(parts) > 1 {
			return p, fmt.Errorf("maximum restart count not valid with restart policy of \"always\"")
		}
	case "no":
		// do nothing
	case "on-failure":
		if len(parts) > 2 {
			return p, fmt.Errorf("restart count format is not valid, usage: 'on-failure:N' or 'on-failure'")
		}
		if len(parts) == 2 {
			count, err := strconv.Atoi(parts[1])
			if err != nil {
				return p, err
			}

			p.MaximumRetryCount = count
		}
	default:
		return p, fmt.Errorf("invalid restart policy %s", name)
	}

	return p, nil
}

func parseKeyValueOpts(opts opts.ListOpts) ([]KeyValuePair, error) {
	out := make([]KeyValuePair, opts.Len())
	for i, o := range opts.GetAll() {
		k, v, err := parsers.ParseKeyValueOpt(o)
		if err != nil {
			return nil, err
		}
		out[i] = KeyValuePair{Key: k, Value: v}
	}
	return out, nil
}

func ParseDevice(device string) (DeviceMapping, error) {
	src := ""
	dst := ""
	permissions := "rwm"
	arr := strings.Split(device, ":")
	switch len(arr) {
	case 3:
		permissions = arr[2]
		fallthrough
	case 2:
		dst = arr[1]
		fallthrough
	case 1:
		src = arr[0]
	default:
		return DeviceMapping{}, fmt.Errorf("Invalid device specification: %s", device)
	}

	if dst == "" {
		dst = src
	}

	deviceMapping := DeviceMapping{
		PathOnHost:        src,
		PathInContainer:   dst,
		CgroupPermissions: permissions,
	}
	return deviceMapping, nil
}
