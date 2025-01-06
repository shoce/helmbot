/*

GoGet
GoFmt
GoBuildNull

*/

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "time/tzdata"

	yaml "gopkg.in/yaml.v3"

	helmaction "helm.sh/helm/v3/pkg/action"
	helmchart "helm.sh/helm/v3/pkg/chart"
	helmloader "helm.sh/helm/v3/pkg/chart/loader"
	helmcli "helm.sh/helm/v3/pkg/cli"
	helmdownloader "helm.sh/helm/v3/pkg/downloader"
	helmgetter "helm.sh/helm/v3/pkg/getter"
	helmrepo "helm.sh/helm/v3/pkg/repo"
	//kubernetes "k8s.io/client-go/kubernetes"
	//krest "k8s.io/client-go/rest"
)

const (
	SPAC = "    "
	TAB  = "\t"
	NL   = "\n"

	ServerPackagesUpgradeInterval = 33 * time.Second

	UpdateHashIdReString = "#([-a-z]+)#([-a-z]+)#([a-z0-9]+)$"

	ValuesLatestHashFilenameSuffix   = "values.latest.hash.text"
	ValuesDeployedHashFilenameSuffix = "values.deployed.hash.text"
	ValuesReportedHashFilenameSuffix = "values.reported.hash.text"
	PermitHashFilenameSuffix         = "values.permit.hash.text"
)

var (
	DEBUG bool

	LogUTCTime bool

	LocalZone string

	ServerHostname string

	ConfigDir      string
	ConfigFilename string

	ValuesMinioUrl      string
	ValuesMinioUsername string
	ValuesMinioPassword string

	ValuesMinioUrlHost string
	ValuesMinioUrlPath string

	Config   HelmbotConfig
	Packages []PackageConfig

	ListenAddr string

	TgToken                 string
	TgBotUserId             int64
	TgWebhookHost           string
	TgWebhookUrl            string
	TgWebhookToken          string
	TgWebhookMaxConnections int64 = 1

	TgChatIds             []int64
	TgBossUserIds         []int64
	TgParseMode           = "MarkdownV2"
	TgDisableNotification = false

	UpdateHashIdRe *regexp.Regexp
)

func init() {
	var err error

	LocalZone = time.Now().Local().Format("-0700")
	if LocalZone == "+0000" {
		LocalZone = "Z"
	}

	UpdateHashIdRe, err = regexp.Compile(UpdateHashIdReString)
	if err != nil {
		log("ERROR `%s` regexp compile error: %s", UpdateHashIdReString, err)
		os.Exit(1)
	}

	if os.Getenv("DEBUG") != "" {
		DEBUG = true
		log("DEBUG==true")
	}

	ServerHostname = os.Getenv("ServerHostname")
	if ServerHostname == "" {
		log("ERROR empty ServerHostname env var")
		os.Exit(1)
	}

	ConfigDir = os.Getenv("ConfigDir")
	if ConfigDir == "" {
		log("ERROR empty ConfigDir env var")
		os.Exit(1)
	}
	if !path.IsAbs(ConfigDir) {
		log("ERROR ConfigDir `%s` must be an absolute path", ConfigDir)
		os.Exit(1)
	}
	if !dirExists(ConfigDir) {
		log("ERROR ConfigDir `%s` does not exist", ConfigDir)
		os.Exit(1)
	}
	log("DEBUG ConfigDir==%s", ConfigDir)

	ConfigFilename = os.Getenv("ConfigFilename")
	if ConfigFilename == "" {
		log("ERROR empty ConfigFilename env var")
	}

	ValuesMinioUrl = os.Getenv("ValuesMinioUrl")
	if ValuesMinioUrl == "" {
		log("WARNING empty ValuesMinioUrl env var")
	} else if u, err := url.Parse(ValuesMinioUrl); err != nil {
		log("ERROR ValuesMinioUrl `%s` parse error: %s", ValuesMinioUrl, err)
		os.Exit(1)
	} else {
		ValuesMinioUrlHost = u.Host
		ValuesMinioUrlPath = u.Path
	}
	log("DEBUG ValuesMinioUrl==`%s`", ValuesMinioUrl)

	ValuesMinioUsername = os.Getenv("ValuesMinioUsername")
	if ValuesMinioUsername == "" && ValuesMinioUrlHost != "" {
		log("WARNING empty ValuesMinioUsername env var")
	}

	ValuesMinioPassword = os.Getenv("ValuesMinioPassword")
	if ValuesMinioPassword == "" && ValuesMinioUrlHost != "" {
		log("WARNING empty ValuesMinioPassword env var")
	}

	ListenAddr = os.Getenv("ListenAddr")
	if ListenAddr == "" {
		ListenAddr = ":80"
	}

	TgToken = os.Getenv("TgToken")
	if TgToken == "" {
		log("ERROR empty TgToken env var")
		os.Exit(1)
	}

	if TgToken != "" {
		botuserid := strings.Split(TgToken, ":")[0]
		userid, err := strconv.Atoi(botuserid)
		if err != nil {
			log("ERROR invalid bot user id:`%s`", botuserid)
			os.Exit(1)
		}
		TgBotUserId = int64(userid)
	}
	if TgBotUserId == 0 {
		log("ERROR empty or invalid bot user id")
		os.Exit(1)
	}

	TgWebhookHost = os.Getenv("TgWebhookHost")
	if TgWebhookHost == "" {
		log("WARNING empty TgWebhookHost env var")
	}

	TgWebhookUrl = os.Getenv("TgWebhookUrl")
	if TgWebhookUrl == "" {
		log("WARNING empty TgWebhookUrl env var")
	}

	TgWebhookToken = os.Getenv("TgWebhookToken")
	if TgWebhookToken == "" {
		log("WARNING empty TgWebhookToken env var")
	}

	for _, i := range strings.Split(strings.TrimSpace(os.Getenv("TgChatIds")), " ") {
		if i == "" {
			continue
		}
		chatid, err := strconv.Atoi(i)
		if err != nil || chatid == 0 {
			log("WARNING invalid chat id:`%s`", i)
		}
		TgChatIds = append(TgChatIds, int64(chatid))
	}
	if len(TgChatIds) == 0 && TgWebhookUrl != "" {
		log("ERROR empty or invalid TgChatIds env var")
		os.Exit(1)
	}

	for _, i := range strings.Split(strings.TrimSpace(os.Getenv("TgBossUserIds")), " ") {
		if i == "" {
			continue
		}
		userid, err := strconv.Atoi(i)
		if err != nil || userid == 0 {
			log("WARNING invalid user id `%s`", i)
		}
		TgBossUserIds = append(TgBossUserIds, int64(userid))
	}
	if len(TgBossUserIds) == 0 {
		log("WARNING empty or invalid TgBossUserIds env var")
	}
}

func main() {
	var err error

	if TgWebhookUrl != "" {
		log("TgWebhookUrl==`%s` so setting webhook with telegram to receive updates.", TgWebhookUrl)
		err = TgSetWebhook(TgWebhookUrl, []string{"message", "channel_post"}, TgWebhookToken)
		if err != nil {
			log("TgSetWebhook: %+v", err)
			os.Exit(1)
		}

		http.HandleFunc("/", Webhook)

		go func() {
			for {
				log("http: serving requests on `%s`.", ListenAddr)
				err := http.ListenAndServe(ListenAddr, nil)
				if err != nil {
					log("ERROR http: %+v", err)
				}
				retryinterval := 11 * time.Second
				log("http: retrying in %s.", retryinterval)
				time.Sleep(retryinterval)
			}
		}()
	} else {
		log("TgWebhookUrl is empty so this instance will not receive telegram updates.")
	}

	go func() {
		for {
			t0 := time.Now()
			err := ServerPackagesUpgrade()
			if err != nil {
				log("ERROR packages: %+v", err)
			}
			tdur := time.Now().Sub(t0)
			if tdur < ServerPackagesUpgradeInterval {
				sleepdur := ServerPackagesUpgradeInterval - tdur
				log("DEBUG packages sleeping %s", sleepdur.Truncate(time.Second))
				time.Sleep(sleepdur)
			}
		}
	}()

	log("start done.")

	for {
		time.Sleep(11 * time.Second)
	}
}

func Webhook(w http.ResponseWriter, r *http.Request) {
	var err error
	if TgWebhookToken != "" && r.Header.Get("X-Telegram-Bot-Api-Secret-Token") != TgWebhookToken {
		log("WARNING Webhook request with invalid X-Telegram-Bot-Api-Secret-Token header")
		w.WriteHeader(http.StatusOK)
		return
	}

	var rbody []byte
	rbody, err = io.ReadAll(r.Body)
	if err != nil {
		log("ERROR Webhook io.ReadAll r.Body: %v", err)
		w.WriteHeader(http.StatusOK)
		return
	}

	if DEBUG {
		log("DEBUG Webhook %s %s %s: %s", r.Method, r.URL, r.Header.Get("Content-Type"), strings.ReplaceAll(string(rbody), NL, " <nl> "))
	}

	w.WriteHeader(http.StatusOK)

	var rupdate TgUpdate
	err = json.NewDecoder(bytes.NewBuffer(rbody)).Decode(&rupdate)
	if err != nil {
		log("ERROR Webhook json.Decoder.Decode: %v", err)
		return
	}

	if rupdate.ChannelPost.MessageId != 0 {
		rupdate.Message = rupdate.ChannelPost
	}

	if DEBUG {
		log("DEBUG Webhook TgUpdate: %+v", rupdate)
	}

	if !slices.Contains(TgChatIds, rupdate.Message.Chat.Id) {
		log("DEBUG Webhook reply to message chat id not valid")
		return
	}
	log("DEBUG Webhook reply to message chat id valid")

	if rupdate.Message.ReplyToMessage.From.Id != TgBotUserId && !slices.Contains(TgChatIds, rupdate.Message.ReplyToMessage.SenderChat.Id) {
		log("DEBUG Webhook reply to message user id not valid")
		return
	}
	log("DEBUG Webhook reply to message user id valid")

	UpdateHashIdSubmatch := UpdateHashIdRe.FindStringSubmatch(rupdate.Message.ReplyToMessage.Text)
	if len(UpdateHashIdSubmatch) == 0 {
		log("DEBUG Webhook reply to message text not valid")
		return
	}
	log("DEBUG Webhook reply to message text valid")

	if !slices.Contains(TgChatIds, rupdate.Message.Chat.Id) {
		log("DEBUG Webhook message chat id not valid")
		return
	}
	log("DEBUG Webhook message chat id valid")

	msgtext := strings.TrimSpace(rupdate.Message.Text)
	if msgtext != "NOW" {
		log("DEBUG Webhook message text not valid")
		return
	}
	log("DEBUG Webhook message text valid")

	if !slices.Contains(TgBossUserIds, rupdate.Message.From.Id) && !slices.Contains(TgChatIds, rupdate.Message.ReplyToMessage.SenderChat.Id) {
		log("DEBUG Webhook message user id not valid")
		if err := tglog(
			rupdate.Message.Chat.Id, rupdate.Message.MessageId,
			"*Your request to force update %s is NOT accepted.*"+NL+NL+"Check helmbot TgBossUserIds config value.",
		); err != nil {
			log("ERROR tglog: %v", err)
		}
		return
	}
	log("DEBUG Webhook message user id valid")

	log("DEBUG Webhook update hash id submatch: %+v", UpdateHashIdSubmatch)

	UpdateHashId := UpdateHashIdSubmatch[0]
	log("Webhook update hash id: %s", UpdateHashId)
	UpdateHelmName := UpdateHashIdSubmatch[1]
	log("Webhook update helm name: %s", UpdateHelmName)
	UpdateEnvName := UpdateHashIdSubmatch[2]
	log("Webhook update env name: %s", UpdateEnvName)
	UpdateValuesHash := UpdateHashIdSubmatch[3]
	log("Webhook update values hash: %s", UpdateValuesHash)

	PackageName := fmt.Sprintf("%s-%s", UpdateHelmName, UpdateEnvName)
	PackageDir := path.Join(ConfigDir, PackageName)

	PackageLatestDir := path.Join(PackageDir, "latest")
	PackageReportedDir := path.Join(PackageDir, "reported")
	PackageDeployedDir := path.Join(PackageDir, "deployed")

	if DEBUG {
		log(
			"DEBUG PackageLatestDir:%s PackageReportedDir:%s PackageDeployedDir:%s",
			PackageLatestDir, PackageReportedDir, PackageDeployedDir,
		)
	}

	deployedvalueshashpath := fmt.Sprintf("%s.%s.%s", UpdateHelmName, UpdateEnvName, ValuesDeployedHashFilenameSuffix)
	var deployedvalueshash string
	if err := GetValuesText(deployedvalueshashpath, &deployedvalueshash); err != nil {
		log("ERROR `%s` could not be read: %v", deployedvalueshashpath, err)
		if err := tglog(
			rupdate.Message.Chat.Id, rupdate.Message.MessageId,
			"*INTERNAL ERROR*",
		); err != nil {
			log("ERROR tglog: %v", err)
		}
		return
	}

	log("deployed values hash: %s", deployedvalueshash)
	if UpdateValuesHash == deployedvalueshash {
		log("DEBUG latest and deployed values hashes match")
		if err := tglog(
			rupdate.Message.Chat.Id, rupdate.Message.MessageId,
			"*THIS UPDATE IS ALREADY DEPLOYED*",
		); err != nil {
			log("ERROR tglog: %v", err)
		}
		return
	}

	reportedvalueshashpath := fmt.Sprintf("%s.%s.%s", UpdateHelmName, UpdateEnvName, ValuesReportedHashFilenameSuffix)
	var reportedvalueshash string
	if err := GetValuesText(reportedvalueshashpath, &reportedvalueshash); err != nil {
		log("ERROR `%s` could not be read: %v", reportedvalueshashpath, err)
		if err := tglog(
			rupdate.Message.Chat.Id, rupdate.Message.MessageId,
			"*INTERNAL ERROR*",
		); err != nil {
			log("ERROR tglog: %v", err)
		}
		return
	}

	log("DEBUG reported values hash: %s", reportedvalueshash)
	if UpdateValuesHash != reportedvalueshash {
		log("DEBUG latest and reported values hashes mismatch")
		if err := tglog(
			rupdate.Message.Chat.Id, rupdate.Message.MessageId,
			"*THIS IS NOT THE LAST AVAILABLE UPDATE*"+NL+NL+"Only the last available update can be forced.",
		); err != nil {
			log("ERROR tglog: %v", err)
		}
		return
	}
	log("DEBUG latest and reported values hashes match")

	log("DEBUG Webhook all checks passed")

	permithashpath := fmt.Sprintf("%s.%s.%s", UpdateHelmName, UpdateEnvName, PermitHashFilenameSuffix)
	log("DEBUG Webhook creating %s file", permithashpath)

	if err := PutValuesText(permithashpath, UpdateValuesHash); err != nil {
		log("ERROR Webhook %s file could not be written: %v", permithashpath, err)
		if err := tglog(
			rupdate.Message.Chat.Id, rupdate.Message.MessageId,
			"*INTERNAL ERROR*",
		); err != nil {
			log("ERROR tglog: %v", err)
		}
		return
	}

	log("DEBUG Webhook created %s file", permithashpath)

	if err := tglog(
		rupdate.Message.Chat.Id, rupdate.Message.MessageId,
		"*FORCE UPDATE NOW IS ACCEPTED.*"+
			NL+NL+
			"THIS UPDATE WILL START IN FEW MINUTES."+
			NL+NL+
			"`%s`",
		UpdateHashId,
	); err != nil {
		log("ERROR tglog: %v", err)
	}

	log("DEBUG Webhook finished %s", UpdateHashId)
}

func ServerPackagesUpgrade() (err error) {
	if DEBUG {
		log("DEBUG packages hostname:%s ", ServerHostname)
	}

	helmactioncfg := new(helmaction.Configuration)
	err = helmactioncfg.Init(helmcli.New().RESTClientGetter(), "", "", log)
	if err != nil {
		return err
	}

	installedreleases, err := helmaction.NewList(helmactioncfg).Run()
	if err != nil {
		return err
	}

	if DEBUG {
		log("DEBUG packages installed releases count: %d ", len(installedreleases))
		/*
			for _, r := range installedreleases {
				log(
					"DEBUG packages installed release name:%s version:%s namespace:%s ",
					r.Name, r.Chart.Metadata.Version, r.Namespace,
				)
			}
		*/
	}

	err = GetValuesFile(ConfigFilename, nil, &Config)
	if err != nil {
		log("WARNING packages GetValues %s: %v", ConfigFilename, err)
		return
	}

	if DEBUG {
		//log("DEBUG packages Config: %+v", Config)
	}

	Packages, err = ProcessServersPackages(Config.Servers)
	if err != nil {
		log("ERROR packages ProcessServersPackages: %v", err)
		return
	}

	//log("packages Packages count: %d", len(Packages))

	helmenvsettings := helmcli.New()

	/*
		log("packages env settings %+v", helmenvsettings)
		if err := os.MkdirAll("/opt/helmbot/helm/cache/", 0750); err != nil {
			return err
		}
		helmenvsettings.RegistryConfig = "/opt/helmbot/helm/registry-config.yaml"
		helmenvsettings.RepositoryConfig = "/opt/helmbot/helm/repository-config.yaml"
		helmenvsettings.RepositoryCache = "/opt/helmbot/helm/cache/"
		log("packages env settings %+v", helmenvsettings)
	*/

	helmgetterall := helmgetter.All(helmenvsettings)
	if DEBUG {
		//log("DEBUG packages helmgetterall: %+v", helmgetterall)
	}

	/*
		kconfig, err := krest.InClusterConfig()
		if err != nil {
			return err
		}
		if DEBUG {
			//log("DEBUG packages kconfig: %+v", kconfig)
		}

			kclientset, err := kubernetes.NewForConfig(kconfig)
			if err != nil {
				return err
			}
			if DEBUG {
				//log("DEBUG packages kclientset: %+v", kclientset)
			}
	*/

	for _, p := range Packages {
		var chartfull *helmchart.Chart

		timenowhour := fmt.Sprintf("%02d", time.Now().In(p.TimezoneLocation).Hour())

		log("helm. "+"%s AlwaysForceNow:%v AllowedHours:%v Timezone:%s TimeNowHour:%v ", p.Name, *p.AlwaysForceNow, p.AllowedHoursList, *p.Timezone, timenowhour)

		err = GetValues("global.values.yaml", &p.HelmGlobalValuesText, p.HelmGlobalValues)
		if err != nil {
			return fmt.Errorf("GetValues `global.values.yaml`: %w", err)
		}

		err = GetValues(fmt.Sprintf("%s.values.yaml", p.HelmName), &p.HelmValuesText, p.HelmValues)
		if err != nil {
			return fmt.Errorf("GetValues `%s.values.yaml`: %w", p.HelmName, err)
		}

		err = GetValues(fmt.Sprintf("%s.%s.values.yaml", p.HelmName, p.EnvName), &p.HelmEnvValuesText, p.HelmEnvValues)
		if err != nil {
			return fmt.Errorf("GetValues `%s.%s.values.yaml`: %w", p.HelmName, p.EnvName, err)
		}

		//log("helm. "+"package config:%+v / "+NL+"// ", p)

		//log("helm. "+"repo address:%s username:%s password:%s", p.HelmRepo.Address, p.HelmRepo.Username, p.HelmRepo.Password)

		if p.HelmRepo.Address != "" {

			chartrepo, err := helmrepo.NewChartRepository(
				&helmrepo.Entry{
					Name:                  fmt.Sprintf("helm.%s.%s", p.HelmName, p.EnvName),
					URL:                   p.HelmRepo.Address,
					Username:              p.HelmRepo.Username,
					Password:              p.HelmRepo.Password,
					InsecureSkipTLSverify: false,
					PassCredentialsAll:    false,
				},
				helmgetterall,
			)
			if err != nil {
				return fmt.Errorf("NewChartRepository %w", err)
			}
			//log("helm. "+"chart repo: %+v", chartrepo)

			indexfilepath, err := chartrepo.DownloadIndexFile()
			if err != nil {
				return fmt.Errorf("DownloadIndexFile %w", err)
			}
			//log("helm. "+"chart repo index file path: %v", indexfilepath)

			idx, err := helmrepo.LoadIndexFile(indexfilepath)
			if err != nil {
				return fmt.Errorf("LoadIndexFile %w", err)
			}

			var chartversion *helmrepo.ChartVersion
			for chartname, chartversions := range idx.Entries {
				if chartname != p.HelmName {
					continue
				}

				if len(chartversions) == 0 {
					return fmt.Errorf("chart repo index: %s: zero chart versions")
				}

				if p.HelmChartVersion != "" {
					for _, v := range chartversions {
						if v.Version == p.HelmChartVersion {
							chartversion = v
						}
					}
				} else {
					sort.Sort(sort.Reverse(chartversions))
					chartversion = chartversions[0]
				}
			}

			if chartversion == nil {
				return fmt.Errorf("helm. "+"chart repo index: helm chart %s: ERROR no chart version found ", p.HelmName)
			}

			if len(chartversion.URLs) == 0 {
				return fmt.Errorf("helm. "+"chart %s: ERROR no chart urls ", p.HelmName)
			}

			charturl, err := helmrepo.ResolveReferenceURL(p.HelmRepo.Address, chartversion.URLs[0])
			if err != nil {
				return err
			}

			//log("helm. "+SPAC+"chart url: %v ", charturl)

			chartdownloader := helmdownloader.ChartDownloader{Getters: helmgetterall}
			chartdownloader.Options = append(chartdownloader.Options, helmgetter.WithUserAgent("helmbot"))
			if p.HelmRepo.Username != "" {
				chartdownloader.Options = append(chartdownloader.Options, helmgetter.WithBasicAuth(p.HelmRepo.Username, p.HelmRepo.Password))
			}

			var chartpath string

			chartpath, _, err = chartdownloader.DownloadTo(charturl, chartversion.Version, "")
			if err != nil {
				return err
			}

			log("helm. DEBUG "+SPAC+"chart downloaded to %s ", chartpath)

			// https://pkg.go.dev/helm.sh/helm/v3/pkg/chart/loader#Load
			chartfull, err = helmloader.Load(chartpath)
			if err != nil {
				return fmt.Errorf("helmloader.Load `%s`: %w", chartpath, err)
			}

			if chartfull == nil {
				return fmt.Errorf("chart downloaded from repo is nil")
			}

		} else if p.HelmChartAddress == "" {

			log("DEBUG package %s HelmChartAddress==%s", p.Name, p.HelmChartAddress)
			continue

		} else if p.HelmChartLocalFilename == "" {

			if path.IsAbs(p.HelmChartLocalFilename) && strings.HasSuffix(p.HelmChartLocalFilename, ".tgz") {
				if chartfile, err := os.Open(p.HelmChartLocalFilename); err != nil {
					log("ERROR package %s HelmChartLocalFilename %s os.Open: %v", p.Name, p.HelmChartLocalFilename, err)
				} else {
					chartfull, err = helmloader.LoadArchive(chartfile)
					if err != nil {
						log("ERROR package %s HelmChartLocalFilename %s LoadArchive: %v", p.Name, p.HelmChartLocalFilename, err)
					}
					chartfile.Close()
				}
			} else {
				log("WARNING package %s HelmChartLocalFilename==%s is not a .tgz file", p.Name, p.HelmChartLocalFilename)
			}

		} else {

			log("WARNING PACKAGE %s has no HelmRepoAddress, HelmChartAddress, HelmChartLocalFilename", p.Name)
			continue

		}

		log("helm. "+SPAC+"chart version==%s len(values)==%d", chartfull.Metadata.Version, len(chartfull.Values))

		// https://pkg.go.dev/helm.sh/helm/v3@v3.16.3/pkg/chart#Metadata
		p.HelmImagesValues[p.HelmChartVersionKey] = chartfull.Metadata.Version

		err = drlatestyaml(p.HelmEnvValues, Config.DrLatestYaml, &p.HelmImagesValues)
		if err != nil {
			return fmt.Errorf("drlatestyaml %s.%s: %w", p.HelmName, p.EnvName, err)
		}

		p.HelmImagesValuesList, p.HelmImagesValuesText, err = ImagesValuesToList(p.HelmImagesValues)

		allvaluestext := p.HelmValuesText + p.HelmEnvValuesText + p.HelmImagesValuesText
		p.ValuesHash = fmt.Sprintf("%x", sha256.Sum256([]byte(allvaluestext)))[:10]

	}

	/*

		installedhelmversion := ""
		for _, r := range installedreleases {
			if r.Name == p.Name && r.Namespace == p.Namespace {
				installedhelmversion = r.Chart.Metadata.Version
			}
		}

		helmversionstatus := "=>"
		if installedhelmversion == chartversion.Version {
			helmversionstatus = "=="
		}
		log("helm. "+SPAC+"chart version: %s %s %s ", installedhelmversion, helmversionstatus, chartversion.Version)


			//
			// READ DEPLOYED
			//

			DeployedHelmValuesTextPath := fmt.Sprintf("%s/deployed/%s.values.yaml", PackageDir, p.HelmName)
			DeployedHelmValuesTextBytes, err := os.ReadFile(DeployedHelmValuesTextPath)
			if err != nil {
				log("os.ReadFile: %s", err)
			}

			DeployedHelmEnvValuesTextPath := fmt.Sprintf("%s/deployed/%s.%s.values.yaml", PackageDir, p.HelmName, p.EnvName)
			DeployedHelmEnvValuesTextBytes, err := os.ReadFile(DeployedHelmEnvValuesTextPath)
			if err != nil {
				log("os.ReadFile: %s", err)
			}

			DeployedImagesValuesTextPath := fmt.Sprintf("%s/deployed/%s.%s.images.values.yaml", PackageDir, p.HelmName, p.EnvName)
			DeployedImagesValuesTextBytes, err := os.ReadFile(DeployedImagesValuesTextPath)
			if err != nil {
				log("os.ReadFile: %s", err)
			}
			DeployedImagesValuesText := string(DeployedImagesValuesTextBytes)

			ReportedValuesHashPath := fmt.Sprintf("%s.%s.%s", PackageDir, p.HelmName, p.EnvName, ValuesReportedHashFilenameSuffix)
			ReportedValuesHashBytes, err := os.ReadFile(ReportedValuesHashPath)
			if err != nil {
				//log("os.ReadFile: %s", err)
				ReportedValuesHashBytes = []byte{}
			}
			ReportedValuesHash := string(ReportedValuesHashBytes)

			var ReportedPermitHash string
			permithashpath := fmt.Sprintf("%s.%s.%s", p.HelmName, p.EnvName, PermitHashFilenameSuffix)
			err = GetValuesText(permithashpath, &ReportedPermitHash)
			if err != nil {
				log("GetValuesText `%s`: %v", permithashpath, err)
			}

			toreport := false

			if p.HelmValuesText != string(DeployedHelmValuesTextBytes) {
				log("helm. " + SPAC + "HelmValuesText diff ")
				toreport = true
			}

			if p.HelmEnvValuesText != string(DeployedHelmEnvValuesTextBytes) {
				log("helm. " + SPAC + "HelmEnvValuesText diff ")
				toreport = true
			}

			if p.HelmImagesValuesText != DeployedImagesValuesText {
				log("helm. " + SPAC + "ImagesValuesText diff ")
				toreport = true

				DeployedImagesValuesMap := make(map[string]string)
				d := yaml.NewDecoder(bytes.NewReader(DeployedImagesValuesTextBytes))
				for {
					if err := d.Decode(&DeployedImagesValuesMap); err != nil {
						if err != io.EOF {
							return fmt.Errorf("yaml Decode %w", err)
						}
						break
					}
				}

				//ansibold := func(s string) string { return "\033[1m" + s + "\033[0m" }
				//ansidim := func(s string) string { return "\033[2m" + s + "\033[0m" }
				//ansiitalic := func(s string) string { return "\033[3m" + s + "\033[0m" }
				//ansiunderline := func(s string) string { return "\033[4m" + s + "\033[0m" }
				//ansistrikethru := func(s string) string { return "\033[9m" + s + "\033[0m" }
				//ansired := func(s string) string { return "\033[31m" + s + "\033[0m" }
				//ansibrightred := func(s string) string { return "\033[91m" + s + "\033[0m" }
				imagesvaluesdiff := ""
				iv1, iv2 := DeployedImagesValuesMap, p.HelmImagesValues
				for name, v1 := range iv1 {
					if v2, ok := iv2[name]; ok {
						if v2 != v1 {
							imagesvaluesdiff += fmt.Sprintf("<> "+"%s: %#v => %#v"+" / ", name, v1, v2)
						}
					} else {
						imagesvaluesdiff += fmt.Sprintf("-- "+"%s: %#v"+" / ", name, v1)
					}
				}
				for name, v2 := range iv2 {
					if _, ok := iv1[name]; !ok {
						imagesvaluesdiff += fmt.Sprintf("++ "+"%s: %#v"+" / ", name, v2)
					}
				}
				log("helm. "+SPAC+"ImagesValues diff: // %s // ", imagesvaluesdiff)

			}

			if p.ValuesHash == ReportedValuesHash {
				log("helm. " + SPAC + "ValuesHash same ")
				toreport = false
			}

			reported := false

			if toreport {

				//
				// WRITE LATEST
				//

				err = os.RemoveAll(PackageLatestDir)
				if err != nil {
					return fmt.Errorf("os.RemoveAll `%s`: %w", PackageLatestDir, err)
				}

				err = os.MkdirAll(PackageLatestDir, 0700)
				if err != nil {
					return fmt.Errorf("os.MkdirAll `%s`: %w", PackageLatestDir, err)
				}

				HelmValuesTextPath := fmt.Sprintf("%s/%s.values.yaml", PackageLatestDir, p.HelmName)
				err = os.WriteFile(HelmValuesTextPath, []byte(p.HelmValuesText), 0600)
				if err != nil {
					return fmt.Errorf("os.WriteFile `%s`: %w", HelmValuesTextPath, err)
				}

				HelmEnvValuesTextPath := fmt.Sprintf("%s/%s.%s.values.yaml", PackageLatestDir, p.HelmName, p.EnvName)
				err = os.WriteFile(HelmEnvValuesTextPath, []byte(p.HelmEnvValuesText), 0600)
				if err != nil {
					return fmt.Errorf("os.WriteFile `%s`: %w", HelmEnvValuesTextPath, err)
				}

				ImagesValuesTextPath := fmt.Sprintf("%s/%s.%s.images.values.yaml", PackageLatestDir, p.HelmName, p.EnvName)
				err = os.WriteFile(ImagesValuesTextPath, []byte(p.HelmImagesValuesText), 0600)
				if err != nil {
					return fmt.Errorf("os.WriteFile `%s`: %w", ImagesValuesTextPath, err)
				}

				ValuesHashPath := fmt.Sprintf("%s.%s.%s", p.HelmName, p.EnvName, ValuesLatestHashFilenameSuffix)
				err = os.WriteFile(ValuesHashPath, []byte(p.ValuesHash), 0600)
				if err != nil {
					return fmt.Errorf("os.WriteFile `%s`: %w", ValuesHashPath, err)
				}

				log("helm. "+SPAC+"#%s#%s#%s latest ", p.HelmName, p.EnvName, p.ValuesHash)

				//
				// REPORT
				//

				err = os.RemoveAll(PackageReportedDir)
				if err != nil {
					return fmt.Errorf("os.RemoveAll `%s`: %w", PackageReportedDir, err)
				}

				err = os.Rename(PackageLatestDir, PackageReportedDir)
				if err != nil {
					return fmt.Errorf("os.Rename `%s` `%s`: %w", PackageLatestDir, PackageReportedDir, err)
				}

				log("helm. "+SPAC+"#%s#%s#%s reported ", p.HelmName, p.EnvName, p.ValuesHash)

				ReportedValuesHash = p.ValuesHash

			}

			if ReportedValuesHash != "" {
				reported = true
			}

			ForceNow := false
			if reported && ReportedPermitHash == ReportedValuesHash {
				ForceNow = true
			}

			todeploy := false

			if p.AlwaysForceNow != nil && *p.AlwaysForceNow {
				todeploy = true
			}

			if slices.Contains(p.AllowedHoursList, timenowhour) {
				todeploy = true
			}

			if ForceNow {
				todeploy = true
			}

			if reported && todeploy {

				//
				// DEPLOY
				//

				err = os.RemoveAll(PackageDeployedDir)
				if err != nil {
					return fmt.Errorf("os.RemoveAll `%s`: %w", PackageDeployedDir, err)
				}

				err = os.Rename(PackageReportedDir, PackageDeployedDir)
				if err != nil {
					return fmt.Errorf("os.Rename `%s` `%s`: %w", PackageReportedDir, PackageDeployedDir, err)
				}

				namespaceexists := false
				if kns, err := kclientset.CoreV1().Namespaces().Get(context.TODO(), p.Namespace, kmetav1.GetOptions{}); kerrors.IsNotFound(err) {
					// namespaceexists = false
				} else if err != nil {
					return err
				} else if kns.Name == p.Namespace {
					namespaceexists = true
				}

				if !namespaceexists {
					pnamespace := &kcorev1.Namespace{
						ObjectMeta: kmetav1.ObjectMeta{
							Name: p.Namespace,
						},
					}
					if _, err := kclientset.CoreV1().Namespaces().Create(context.TODO(), pnamespace, kmetav1.CreateOptions{}); err != nil {
						return err
					}
				}

				isinstalled := false
				for _, r := range installedreleases {
					if r.Name == p.Name && r.Namespace == p.Namespace {
						isinstalled = true
					}
				}

				var pkgrelease *helmrelease.Release
				if isinstalled {
					// https://pkg.go.dev/helm.sh/helm/v3/pkg/action#Upgrade
					helmupgrade := helmaction.NewUpgrade(helmactioncfg)
					helmupgrade.DryRun = true
					helmupgrade.Namespace = p.Namespace

					chart := new(helmchart.Chart)
					values := make(map[string]interface{})
					pkgrelease, err = helmupgrade.Run(
						p.Name,
						chart,
						values,
					)
					if err != nil {
						return err
					}
				} else {
					// https://pkg.go.dev/helm.sh/helm/v3/pkg/action#Install
					helminstall := helmaction.NewInstall(helmactioncfg)
					helminstall.DryRun = true
					helminstall.CreateNamespace = true
					helminstall.Namespace = p.Namespace
					helminstall.ReleaseName = p.Name

					chart := new(helmchart.Chart)
					values := make(map[string]interface{})
					pkgrelease, err = helminstall.Run(
						chart,
						values,
					)
					if err != nil {
						return err
					}
				}

				log("helm. "+SPAC+"#%s#%s#%s deployed ", p.HelmName, p.EnvName, p.ValuesHash)
				if pkgrelease == nil {
					log("helm. "+SPAC+"release: %+v ", pkgrelease)
				} else {
					log("helm. "+SPAC+"release info: %s ", pkgrelease.Info.Status)
				}

			}

		}

	*/

	return nil
}

func ProcessServersPackages(servers []ServerConfig) (packages []PackageConfig, err error) {
	for _, s := range servers {
		if s.ServerHostname != ServerHostname {
			continue
		}
		if s.AllowedHours != nil {
			s.AllowedHoursList = strings.Split(*s.AllowedHours, " ")
		}
		if s.Timezone == nil || *s.Timezone == "" {
			tzutc := "UTC"
			s.Timezone = &tzutc
			s.TimezoneLocation = time.UTC
		} else {
			s.TimezoneLocation, err = time.LoadLocation(*s.Timezone)
			if err != nil {
				return nil, err
			}
		}
		for _, p := range s.Packages {
			p.Name = fmt.Sprintf("%s-%s", p.HelmName, p.EnvName)

			if p.Namespace == "" {
				p.Namespace = fmt.Sprintf("%s-%s", p.HelmName, p.EnvName)
			}

			p.ServerHostname = &s.ServerHostname

			if p.AllowedHours == nil {
				p.AllowedHours = s.AllowedHours
			}
			if p.AllowedHours != nil {
				p.AllowedHoursList = strings.Split(*p.AllowedHours, " ")
			}

			if p.Timezone == nil {
				p.Timezone = s.Timezone
				p.TimezoneLocation = s.TimezoneLocation
			}

			if p.AlwaysForceNow == nil {
				if s.AlwaysForceNow == nil {
					varfalse := false
					p.AlwaysForceNow = &varfalse
				} else {
					p.AlwaysForceNow = s.AlwaysForceNow
				}
			}

			if p.UpdateDelay == nil {
				p.UpdateDelay = s.UpdateDelay
			}
			if p.TgChatId == nil {
				p.TgChatId = s.TgChatId
			}
			if p.TgMentions == nil {
				p.TgMentions = s.TgMentions
			}

			if p.HelmChartLocalFilename != "" {
				if ff, err := filepath.Glob(path.Join(ConfigDir, p.HelmChartLocalFilename)); err != nil {
					log("WARNING filepath.Glob %s: %s", p.HelmChartLocalFilename, err)
				} else if len(ff) == 0 {
					log("WARNING no files for %s glob found", p.HelmChartLocalFilename)
				} else {
					sort.Strings(ff)
					p.HelmChartLocalFilename = ff[len(ff)-1]
				}
			}

			p.PackageDir = path.Join(ConfigDir, p.Name)
			p.PackageLatestDir = path.Join(p.PackageDir, "latest")
			p.PackageReportedDir = path.Join(p.PackageDir, "reported")
			p.PackageDeployedDir = path.Join(p.PackageDir, "deployed")

			p.HelmGlobalValues = make(map[string]interface{})
			p.HelmValues = make(map[string]interface{})
			p.HelmEnvValues = make(map[string]interface{})
			p.HelmImagesValues = make(map[string]interface{})

			packages = append(packages, p)
		}
	}

	if DEBUG {
		log("ProcessServersPackages servers:%d packages:%d", len(servers), len(packages))
	}

	return packages, nil
}

func GetValuesText(name string, valuestext *string) (err error) {
	if ValuesMinioUrlHost != "" {
		return GetValuesTextMinio(name, valuestext)
	}
	return GetValuesTextFile(name, valuestext)
}

func GetValues(name string, valuestext *string, values interface{}) (err error) {
	if ValuesMinioUrlHost != "" {
		return GetValuesMinio(name, valuestext, values)
	}
	return GetValuesFile(name, valuestext, values)
}

func PutValuesText(name string, valuestext string) (err error) {
	if ValuesMinioUrlHost != "" {
		return PutValuesTextMinio(name, valuestext)
	}
	return PutValuesTextFile(name, valuestext)
}

func GetValuesTextFile(name string, valuestext *string) (err error) {
	filepath := path.Join(ConfigDir, name)

	bb, err := os.ReadFile(filepath)
	if err != nil {
		return err
	}

	if valuestext == nil {
		tempvaluestext := string(bb)
		valuestext = &tempvaluestext
	} else {
		*valuestext = string(bb)
	}

	return nil
}

func GetValuesFile(name string, valuestext *string, values interface{}) (err error) {
	if valuestext == nil {
		var valuestext1 string
		valuestext = &valuestext1
	}

	err = GetValuesTextFile(name, valuestext)
	if err != nil {
		return err
	}

	d := yaml.NewDecoder(strings.NewReader(*valuestext))
	err = d.Decode(values)
	if err != nil {
		return err
	}

	return nil
}

func PutValuesTextFile(name string, valuestext string) (err error) {
	err = os.WriteFile(name, []byte(valuestext), 0644)
	if err != nil {
		log("ERROR WriteFile %s: %v", name, err)
		return err
	}
	return nil
}

type PackageConfig struct {
	Name      string `yaml:"Name"`
	Namespace string `yaml:"Namespace,omitempty"`
	HelmName  string `yaml:"HelmName"`
	EnvName   string `yaml:"EnvName"`

	PackageDir         string
	PackageLatestDir   string
	PackageReportedDir string
	PackageDeployedDir string

	HelmChartVersion    string `yaml:"HelmChartVersion"`
	HelmChartVersionKey string `yaml:"HelmChartVersionKey"`

	HelmChartLocalFilename string `yaml:"HelmChartLocalFilename"`

	HelmChartAddress string `yaml:"HelmChartAddress"`
	HelmRepo         struct {
		Address  string `yaml:"Address"`
		Username string `yaml:"Username"`
		Password string `yaml:"Password"`
	} `yaml:"HelmRepo"`

	ServerHostname *string `yaml:"ServerHostname,omitempty"`
	TgChatId       *int64  `yaml:"TgChatId,omitempty"`
	TgMentions     *string `yaml:"TgMentions,omitempty"`

	Timezone       *string `yaml:"Timezone,omitempty"`
	AllowedHours   *string `yaml:"AllowedHours,omitempty"`
	AlwaysForceNow *bool   `yaml:"AlwaysForceNow,omitempty"`
	ForceNow       bool    `yaml:"ForceNow"`

	UpdateInterval string  `yaml:"UpdateInterval"`
	UpdateDelay    *string `yaml:"UpdateDelay,omitempty"`

	TimezoneLocation *time.Location
	AllowedHoursList []string

	HelmGlobalValuesText string
	HelmValuesText       string
	HelmEnvValuesText    string
	HelmImagesValuesText string

	HelmGlobalValues     map[string]interface{}
	HelmValues           map[string]interface{}
	HelmEnvValues        map[string]interface{}
	HelmImagesValuesList []map[string]interface{}
	HelmImagesValues     map[string]interface{}

	ValuesHash string `yaml:"ValuesHash"`
}

type ServerConfig struct {
	ServerHostname string  `yaml:"ServerHostname"`
	Timezone       *string `yaml:"Timezone,omitempty"`
	AllowedHours   *string `yaml:"AllowedHours,omitempty"`
	AlwaysForceNow *bool   `yaml:"AlwaysForceNow,omitempty"`
	UpdateDelay    *string `yaml:"UpdateDelay,omitempty"`

	TgChatId   *int64  `yaml:"TgChatId,omitempty"`
	TgMentions *string `yaml:"TgMentions,omitempty"`

	Packages []PackageConfig `yaml:"Packages"`

	AllowedHoursList []string
	TimezoneLocation *time.Location
}

type HelmbotConfig struct {
	DrLatestYaml []DrLatestYamlItem `yaml:"DrLatestYaml"`
	Servers      []ServerConfig     `yaml:"Servers"`
}

func log(msg string, args ...interface{}) {
	t := time.Now()
	var tzone string
	if LogUTCTime {
		t = t.UTC()
		tzone = "Z"
	} else {
		t = t.Local()
		tzone = LocalZone
	}
	ts := fmt.Sprintf(
		"%03d:%02d%02d:%02d%02d%s",
		t.Year()%1000, t.Month(), t.Day(), t.Hour(), t.Minute(), tzone,
	)
	fmt.Fprintf(os.Stderr, ts+" "+msg+NL, args...)
}

func dirExists(path string) bool {
	s, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return err == nil && s.IsDir()
}
