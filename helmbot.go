/*

GoGet
GoFmt
GoBuildNull

*/

package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
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

	textcases "golang.org/x/text/cases"
	textlanguage "golang.org/x/text/language"

	dregistry "github.com/rusenask/docker-registry-client/registry"

	helmaction "helm.sh/helm/v3/pkg/action"
	helmchart "helm.sh/helm/v3/pkg/chart"
	helmloader "helm.sh/helm/v3/pkg/chart/loader"
	helmchartutil "helm.sh/helm/v3/pkg/chartutil"
	helmcli "helm.sh/helm/v3/pkg/cli"
	helmdownloader "helm.sh/helm/v3/pkg/downloader"
	helmgetter "helm.sh/helm/v3/pkg/getter"
	helmregistry "helm.sh/helm/v3/pkg/registry"
	helmrelease "helm.sh/helm/v3/pkg/release"
	helmrepo "helm.sh/helm/v3/pkg/repo"

	"github.com/shoce/tg"
)

const (
	SPAC = "    "
	TAB  = "\t"
	NL   = "\n"

	UpdateHashIdReString = "#([-a-z0-9]+)#([-a-z0-9]+)#([a-z0-9]+)$"

	HashLength = 12

	PackagesSleepDuration = 2 * time.Second

	ConfigLocalFilename = "helmbot.config.local.yaml"
)

var (
	VERBOSE bool
	DEBUG   bool

	VERSION string

	ServerPackagesUpdateLastRun time.Time

	LogUTC          bool
	LogTimeZone     string         = "+"
	LogTimeLocation *time.Location = time.UTC

	ServerHostname string

	ConfigDir string

	ConfigFilename     string
	HostConfigFilename string

	PackagesUpgradeInterval time.Duration

	ValuesMinioUrl      string
	ValuesMinioUsername string
	ValuesMinioPassword string

	ValuesMinioUrlHost string
	ValuesMinioUrlPath string

	ConfigLocal HelmbotConfig

	Config   HelmbotConfig
	Packages []PackageConfig

	ListenAddr string

	TgToken                 string
	TgBotUserId             int64
	TgWebhookHost           string
	TgWebhookUrl            string
	TgWebhookToken          string
	TgWebhookMaxConnections int64 = 1
	TgAdminMention          string

	TgChatIds             []int64
	TgBossUserIds         []int64
	TgParseMode           = "MarkdownV2"
	TgDisableNotification = false

	UpdateHashIdRe *regexp.Regexp

	FALSE = false
)

func init() {
	var err error

	hostname, err := os.Hostname()
	log("helmbot version==%v hostname==%v", VERSION, hostname)

	if os.Getenv("LogUTC") != "" {
		LogUTC = true
		log("LogUTC==%v", LogUTC)
	}

	if LogUTC {
		LogTimeLocation = time.UTC
		LogTimeZone = "+"
	} else {
		LogTimeLocation = time.Local
		LogTimeZone = time.Now().Local().Format("-0700")
		LogTimeZone = strings.TrimRight(LogTimeZone, "0")
	}

	UpdateHashIdRe, err = regexp.Compile(UpdateHashIdReString)
	if err != nil {
		log("ERROR regexp %#v compile error: %s", UpdateHashIdReString, err)
		os.Exit(1)
	}

	if os.Getenv("VERBOSE") != "" {
		VERBOSE = true
		log("VERBOSE==%v", VERBOSE)
	}

	if os.Getenv("DEBUG") != "" {
		DEBUG = true
		log("DEBUG==%v", DEBUG)
		// SET VERBOSE IF DEBUG
		if !VERBOSE {
			VERBOSE = true
			log("VERBOSE==%v", VERBOSE)
		}
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
		log("ERROR ConfigDir %v must be an absolute path", ConfigDir)
		os.Exit(1)
	}
	if !dirExists(ConfigDir) {
		log("ERROR ConfigDir %v does not exist", ConfigDir)
		os.Exit(1)
	}
	if DEBUG {
		log("DEBUG ConfigDir==%v", ConfigDir)
	}

	ConfigFilename = os.Getenv("ConfigFilename")
	if DEBUG {
		log("DEBUG ConfigFilename==%v", ConfigFilename)
	}
	HostConfigFilename = os.Getenv("HostConfigFilename")
	if DEBUG {
		log("DEBUG HostConfigFilename==%v", HostConfigFilename)
	}

	if v := os.Getenv("PackagesUpgradeInterval"); v != "" {
		if d, err := time.ParseDuration(v); err != nil {
			log("ERROR parse duration PackagesUpgradeInterval==%v: %s", v, err)
			os.Exit(1)
		} else {
			PackagesUpgradeInterval = d
		}
	} else {
		log("ERROR empty PackagesUpgradeInterval env var")
		os.Exit(1)
	}
	if DEBUG {
		log("DEBUG PackagesUpgradeInterval==%v", PackagesUpgradeInterval)
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
	if DEBUG {
		log("DEBUG ValuesMinioUrl==%v", ValuesMinioUrl)
	}

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

	TgAdminMention = os.Getenv("TgAdminMention")
	if TgAdminMention == "" {
		log("WARNING empty TgAdminMention env var")
	}

	TgWebhookHost = os.Getenv("TgWebhookHost")
	if TgWebhookHost == "" {
		log("WARNING empty TgWebhookHost env var")
	}

	TgWebhookUrl = os.Getenv("TgWebhookUrl")
	if DEBUG {
		log("DEBUG TgWebhookUrl==%v", TgWebhookUrl)
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
		log("ERROR empty or invalid TgBossUserIds env var")
		os.Exit(1)
	}
}

// TODO tglog replacement for logging to a web page

func main() {

	go func() {

		healthmux := http.NewServeMux()
		healthmux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
			health := map[string]interface{}{
				"ok":                      true,
				"PackagesUpgradeInterval": PackagesUpgradeInterval.String(),
				"ServerPackagesUpdateAgo": time.Since(ServerPackagesUpdateLastRun).Truncate(time.Second).String(),
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(health); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		})
		for {
			if err := http.ListenAndServe(":81", healthmux); err != nil {
				log("ERROR healthmux: %+v", err)
				time.Sleep(time.Second)
			}
		}

	}()

	if TgWebhookUrl != "" {

		if DEBUG {
			log("DEBUG TgWebhookUrl==%v so setting webhook with telegram to receive updates.", TgWebhookUrl)
		}
		if err := TgSetWebhook(TgWebhookUrl, []string{"message", "channel_post"}, TgWebhookToken); err != nil {
			log("ERROR TgSetWebhook: %+v", err)
			os.Exit(1)
		}

		http.HandleFunc("/", Webhook)

		go func() {
			for {
				log("webhook serving requests on %v.", ListenAddr)
				err := http.ListenAndServe(ListenAddr, nil)
				if err != nil {
					log("webhook ERROR ListenAndServe: %+v", err)
				}
				retryinterval := 11 * time.Second
				log("webhook retrying ListenAndServe in %v", retryinterval)
				time.Sleep(retryinterval)
			}
		}()

	} else {

		log("TgWebhookUrl is not set so this instance will not register telegram webhook.")

	}

	go func() {
		for {
			ServerPackagesUpdateLastRun = time.Now()

			if err := ServerPackagesUpdate(); err != nil {
				log("packages ERROR update: %+v", err)
			}

			if d := time.Now().Sub(ServerPackagesUpdateLastRun); d < PackagesUpgradeInterval {
				sleepdur := (PackagesUpgradeInterval - d).Truncate(time.Second)
				if DEBUG {
					log("packages DEBUG sleeping %s", sleepdur)
				}
				time.Sleep(sleepdur)
			}
			if DEBUG {
				log("---")
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
	var tgerr error

	if TgWebhookToken != "" && r.Header.Get("X-Telegram-Bot-Api-Secret-Token") != TgWebhookToken {
		log("webhook WARNING request with invalid X-Telegram-Bot-Api-Secret-Token header")
		w.WriteHeader(http.StatusOK)
		return
	}

	var rbody []byte
	rbody, err = io.ReadAll(r.Body)
	if err != nil {
		log("webhook ERROR io.ReadAll r.Body: %v", err)
		w.WriteHeader(http.StatusOK)
		return
	}

	if DEBUG {
		log("webhook DEBUG %s %s %s: %s", r.Method, r.URL, r.Header.Get("Content-Type"), strings.ReplaceAll(string(rbody), NL, " <nl> "))
	}

	w.WriteHeader(http.StatusOK)

	var rupdate tg.Update
	err = json.NewDecoder(bytes.NewBuffer(rbody)).Decode(&rupdate)
	if err != nil {
		log("webhook ERROR json.Decoder.Decode: %v", err)
		return
	}

	if rupdate.ChannelPost.MessageId != 0 {
		rupdate.Message = rupdate.ChannelPost
	}

	if DEBUG {
		log("webhook DEBUG TgUpdate: %+v", rupdate)
	}

	if !slices.Contains(TgChatIds, rupdate.Message.Chat.Id) {
		if DEBUG {
			log("webhook DEBUG reply to message chat id not valid")
		}
		return
	}
	if DEBUG {
		log("webhook DEBUG reply to message chat id valid")
	}

	if rupdate.Message.ReplyToMessage.From.Id != TgBotUserId && !slices.Contains(TgChatIds, rupdate.Message.ReplyToMessage.SenderChat.Id) {
		if DEBUG {
			log("webhook DEBUG reply to message user id not valid")
		}
		return
	}
	if DEBUG {
		log("webhook DEBUG reply to message user id valid")
	}

	UpdateHashIdSubmatch := UpdateHashIdRe.FindStringSubmatch(rupdate.Message.ReplyToMessage.Text)
	if len(UpdateHashIdSubmatch) == 0 {
		if DEBUG {
			log("webhook DEBUG reply to message text not valid")
		}
		return
	}
	if DEBUG {
		log("webhook DEBUG reply to message text valid")
	}

	if !slices.Contains(TgChatIds, rupdate.Message.Chat.Id) {
		if DEBUG {
			log("webhook DEBUG message chat id not valid")
		}
		return
	}
	if DEBUG {
		log("webhook DEBUG message chat id valid")
	}

	msgtext := strings.TrimSpace(rupdate.Message.Text)
	if msgtext != "NOW" {
		if DEBUG {
			log("webhook DEBUG message text not valid")
		}
		return
	}
	if DEBUG {
		log("webhook DEBUG message text valid")
	}

	UpdateHashId := UpdateHashIdSubmatch[0]
	UpdateChartName := UpdateHashIdSubmatch[1]
	UpdateEnvName := UpdateHashIdSubmatch[2]
	UpdateValuesHash := UpdateHashIdSubmatch[3]
	if VERBOSE {
		log("webhook update hash id: %s", UpdateHashId)
		log("webhook update helm name: %s", UpdateChartName)
		log("webhook update env name: %s", UpdateEnvName)
		log("webhook update values hash: %s", UpdateValuesHash)
	}

	p := PackageConfig{ChartName: UpdateChartName, EnvName: UpdateEnvName}

	if !slices.Contains(TgBossUserIds, rupdate.Message.From.Id) && !slices.Contains(TgChatIds, rupdate.Message.ReplyToMessage.SenderChat.Id) {
		if DEBUG {
			log("webhook DEBUG message user id not valid")
		}
		if _, tgerr = tglog(
			tg.Bold("Your request to force update %s-%s is NOT accepted.", p.ChartName, p.EnvName)+NL+NL+tg.Esc("Check helmbot TgBossUserIds config value."),
			rupdate.Message.Chat.Id, rupdate.Message.MessageId, 0,
		); tgerr != nil {
			log("webhook ERROR tglog: %v", tgerr)
		}
		return
	}
	if DEBUG {
		log("webhook DEBUG message user id valid")
	}

	if DEBUG {
		log("webhook DEBUG update hash id submatch: %+v", UpdateHashIdSubmatch)
	}

	var ValuesDeployedHash string
	if err := GetValuesText(p.ValuesDeployedHashFilename(), &ValuesDeployedHash, true); err != nil {
		log("webhook ERROR %v could not be read: %v", p.ValuesDeployedHashFilename(), err)
		if _, tgerr = tglog(
			tg.Bold("INTERNAL ERROR")+NL+
				tg.Esc(TgAdminMention),
			rupdate.Message.Chat.Id, rupdate.Message.MessageId, 0,
		); tgerr != nil {
			log("webhook ERROR tglog: %v", tgerr)
		}
		return
	}

	if DEBUG {
		log("webhook DEBUG deployed values hash: %s", ValuesDeployedHash)
	}
	if UpdateValuesHash == ValuesDeployedHash {
		if DEBUG {
			log("webhook DEBUG latest and deployed values hashes match")
		}
		if _, tgerr = tglog(
			tg.Bold("THIS UPDATE IS ALREADY DEPLOYED"),
			rupdate.Message.Chat.Id, rupdate.Message.MessageId, 0,
		); tgerr != nil {
			log("webhook ERROR tglog: %v", tgerr)
		}
		return
	}

	var ValuesReportedHash string
	if err := GetValuesText(p.ValuesReportedHashFilename(), &ValuesReportedHash, true); err != nil {
		log("webhook ERROR %v could not be read: %v", p.ValuesReportedHashFilename(), err)
		if _, tgerr = tglog(
			tg.Bold("INTERNAL ERROR")+NL+
				tg.Esc(TgAdminMention),
			rupdate.Message.Chat.Id, rupdate.Message.MessageId, 0,
		); tgerr != nil {
			log("webhook ERROR tglog: %v", tgerr)
		}
		return
	}

	if DEBUG {
		log("webhook DEBUG reported values hash: %s", ValuesReportedHash)
	}
	if UpdateValuesHash != ValuesReportedHash {
		if DEBUG {
			log("webhook DEBUG latest and reported values hashes mismatch")
		}
		if _, tgerr = tglog(
			tg.Bold("THIS IS NOT THE LAST AVAILABLE UPDATE")+NL+NL+tg.Esc("Only the last available update can be forced."),
			rupdate.Message.Chat.Id, rupdate.Message.MessageId, 0,
		); tgerr != nil {
			log("webhook ERROR tglog: %v", tgerr)
		}
		return
	}
	if DEBUG {
		log("webhook DEBUG latest and reported values hashes match")
	}

	if DEBUG {
		log("webhook DEBUG all checks passed")
	}

	if DEBUG {
		log("webhook DEBUG creating %v file", p.ValuesPermitHashFilename())
	}

	if err := PutValuesText(p.ValuesPermitHashFilename(), UpdateValuesHash); err != nil {
		log("webhook ERROR %v file could not be written: %v", p.ValuesPermitHashFilename(), err)
		if _, tgerr = tglog(
			tg.Bold("INTERNAL ERROR")+NL+
				tg.Esc(TgAdminMention),
			rupdate.Message.Chat.Id, rupdate.Message.MessageId, 0,
		); tgerr != nil {
			log("webhook ERROR tglog: %v", tgerr)
		}
		return
	}

	if DEBUG {
		log("webhook DEBUG created %v file", p.ValuesPermitHashFilename())
	}

	if _, tgerr = tglog(
		tg.Bold("FORCE UPDATE NOW IS ACCEPTED")+
			NL+NL+
			"THIS UPDATE WILL START IN FEW MINUTES"+
			NL+NL+
			tg.Code(UpdateHashId),
		rupdate.Message.Chat.Id, rupdate.Message.MessageId, 0,
	); tgerr != nil {
		log("webhook ERROR tglog: %v", tgerr)
	}

	if DEBUG {
		log("webhook DEBUG finished %s", UpdateHashId)
	}
}

func ServerPackagesUpdate() (err error) {

	var paused string
	if err := GetValuesTextFile("paused", &paused, false); err == nil {
		// paused packages update - return with no error
		if VERBOSE {
			log("packages update paused")
		}
		return nil
	}

	if ConfigFilename != "" {
		if err := GetValues(ConfigFilename, nil, &Config); err != nil {
			return err
		}
	}

	if HostConfigFilename != "" {
		if err := GetValues(HostConfigFilename, nil, &Config); err != nil {
			return err
		}
	}

	GetValuesFile(ConfigLocalFilename, nil, &ConfigLocal)

	for _, d := range ConfigLocal.DrLatestYaml {
		Config.DrLatestYaml = append(Config.DrLatestYaml, d)
	}
	for _, s := range ConfigLocal.Servers {
		Config.Servers = append(Config.Servers, s)
	}

	if DEBUG {
		//log("packages DEBUG Config==%+v", Config)
	}

	// INSTALLED RELEASES

	// https://pkg.go.dev/helm.sh/helm/v3/pkg/cli
	helmenvsettings := helmcli.New()
	helmactioncfg := new(helmaction.Configuration)
	if err := helmactioncfg.Init(helmenvsettings.RESTClientGetter(), "", "", log); err != nil {
		return err
	}
	installedreleases, err := helmaction.NewList(helmactioncfg).Run()
	if err != nil {
		return err
	}

	/*
		if DEBUG {
			for _, r := range installedreleases {
				log("packages DEBUG Name==%s Namespace==%s Status==%s Revision==%d Version==%s",
					r.Name, r.Namespace, r.Info.Status, r.Version, r.Chart.Metadata.Version,
				)
			}
		}
	*/

	Packages, err = ProcessServersPackages(Config.Servers)
	if err != nil {
		log("packages ERROR ProcessServersPackages: %v", err)
		return err
	}

	for _, p := range Packages {

		var pkgpaused string
		if err := GetValuesTextFile(p.PausedFilename(), &pkgpaused, false); err == nil {
			// paused package update - skip with no error
			p.log("DEBUG update paused")
			continue
		}

		//
		// READ PERMIT HASH
		//

		var PermitHash string
		if err := GetValuesText(p.ValuesPermitHashFilename(), &PermitHash, true); err != nil {
			p.log("ERROR GetValuesText: %v", err)
		}

		updatetimestampfilename := path.Join(ConfigDir, p.UpdateTimestampFilename())
		if updatetimestampfilestat, err := os.Stat(updatetimestampfilename); err == nil {
			p.UpdateTimestamp = updatetimestampfilestat.ModTime()
		}

		// TODO update values but not images.values

		if PermitHash == "" {
			if d := time.Now().Sub(p.UpdateTimestamp).Truncate(time.Second); d < p.UpdateIntervalDuration {
				if DEBUG {
					p.log("DEBUG %v until next update", p.UpdateIntervalDuration-d)
				}
				continue
			}
		}

		timenow := time.Now()
		timenowhour := fmt.Sprintf("%02d", timenow.In(p.TimezoneLocation).Hour())

		if DEBUG {
			p.log("DEBUG Namespace:%s DryRun==%v AlwaysForceNow==%v AllowedHours==%v Timezone==%v TimeNowHour==%v UpdateInterval==%v LocalValues==%#v", p.Namespace, *p.DryRun, *p.AlwaysForceNow, p.AllowedHoursList, *p.Timezone, timenowhour, p.UpdateIntervalDuration, p.LocalValues)
		}

		if DEBUG {
			//p.log("DEBUG config==%#v", p)
			p.log("DEBUG repo.address==%#v chartaddress==%#v chartlocalfilename==%#v", p.ChartRepo.Address, p.ChartAddress, p.ChartLocalFilename)
		}

		//
		// READ LATEST VALUES
		//

		if len(p.LocalValues) == 0 {

			err = GetValues(p.GlobalValuesFilename(), &p.GlobalValuesText, p.GlobalValues)
			if err != nil {
				return err
			}

			err = GetValues(p.ValuesFilename(), &p.ValuesText, p.Values)
			if err != nil {
				return err
			}

			err = GetValues(p.EnvValuesFilename(), &p.EnvValuesText, p.EnvValues)
			if err != nil {
				return err
			}

		}

		//
		// FETCH CHART INFO
		//

		var chartname, chartversion string
		var chartpath string
		var chartfull *helmchart.Chart

		chartdownloader := helmdownloader.ChartDownloader{Getters: helmgetter.All(helmenvsettings)}
		chartdownloader.Options = append(chartdownloader.Options, helmgetter.WithUserAgent("helmbot"))
		if p.ChartRepo.Address != "" && p.ChartRepo.Username != "" {
			chartdownloader.Options = append(chartdownloader.Options, helmgetter.WithBasicAuth(p.ChartRepo.Username, p.ChartRepo.Password))
		}

		if p.ChartRepo.Address != "" {

			chartrepo, err := helmrepo.NewChartRepository(
				&helmrepo.Entry{
					Name:                  fmt.Sprintf("helm.%s.%s", p.ChartName, p.EnvName),
					URL:                   p.ChartRepo.Address,
					Username:              p.ChartRepo.Username,
					Password:              p.ChartRepo.Password,
					InsecureSkipTLSverify: false,
					PassCredentialsAll:    false,
				},
				helmgetter.All(helmenvsettings),
			)
			if err != nil {
				return fmt.Errorf("NewChartRepository %w", err)
			}

			indexfilepath, err := chartrepo.DownloadIndexFile()
			if err != nil {
				return fmt.Errorf("DownloadIndexFile %w", err)
			}
			if DEBUG {
				//p.log("DEBUG chart repo index file path %s", indexfilepath)
			}
			// TODO store chart repo indexes in /opt/helmbot/, not at /root/.cache/helm/

			idx, err := helmrepo.LoadIndexFile(indexfilepath)
			if err != nil {
				return fmt.Errorf("LoadIndexFile %w", err)
			}

			var repochartversion *helmrepo.ChartVersion
			for repochartname, repochartversions := range idx.Entries {
				if repochartname != p.ChartName {
					continue
				}

				if len(repochartversions) == 0 {
					return fmt.Errorf("chart repo index %v: no chart versions", indexfilepath)
				}

				sort.Sort(sort.Reverse(repochartversions))

				if DEBUG {
					var vv []string
					for _, v := range repochartversions {
						vv = append(vv, v.Version)
					}
					p.log("DEBUG repo versions==%+v", vv)
				}

				if p.ChartVersion != "" {
					if DEBUG {
						p.log("DEBUG ChartVersion==%#v", p.ChartVersion)
					}
					for _, v := range repochartversions {
						if v.Version == p.ChartVersion {
							if DEBUG {
								p.log("DEBUG ChartVersion==%#v found in repo", p.ChartVersion)
							}
							repochartversion = v
						}
					}
				} else {
					repochartversion = repochartversions[0]
				}
			}

			if repochartversion == nil {
				return fmt.Errorf("packages chart %s repo index: no chart version found", p.ChartName)
			}

			chartname = repochartversion.Name
			chartversion = repochartversion.Version
			chartpath = path.Join(ConfigDir, fmt.Sprintf("%s-%s.tgz", chartname, chartversion))
			if DEBUG {
				p.log("DEBUG local chartpath==%v exists==%v", chartpath, fileExists(chartpath))
			}

			if !fileExists(chartpath) {
				if len(repochartversion.URLs) == 0 {
					return fmt.Errorf("packages chart %s: no chart urls", p.ChartName)
				}

				charturl, err := helmrepo.ResolveReferenceURL(p.ChartRepo.Address, repochartversion.URLs[0])
				if err != nil {
					return err
				}
				if chartpath, _, err = chartdownloader.DownloadTo(charturl, chartversion, ConfigDir); err != nil {
					return err
				}
			}

		} else if p.ChartAddress != "" {

			chartaddress := p.ChartAddress
			chartaddress = strings.TrimPrefix(chartaddress, "https://")
			chartaddress = strings.TrimPrefix(chartaddress, "oci://")

			hrclient, err := helmregistry.NewClient(helmregistry.ClientOptDebug(true))
			if err != nil {
				return fmt.Errorf("helmregistry.NewClient: %v", err)
			}

			tags, err := hrclient.Tags(chartaddress)
			if err != nil {
				return fmt.Errorf("hrclient.Tags: %v", err)
			}

			if len(tags) == 0 {
				return fmt.Errorf("ChartAddress==%v empty tags list", p.ChartAddress, err)
			}

			if DEBUG {
				p.log("DEBUG tags==%+v", tags)
			}

			chartversion = tags[0]

			if u, err := url.Parse(p.ChartAddress); err != nil {
				return fmt.Errorf("parse ChartAddress==%v: %v", p.ChartAddress, err)
			} else {
				chartname = path.Base(u.Path)
				chartpath = path.Join(ConfigDir, fmt.Sprintf("%s-%s.tgz", chartname, chartversion))
				if DEBUG {
					p.log("DEBUG local chartpath==%v exists==%v", chartpath, fileExists(chartpath))
				}
			}

			if !fileExists(chartpath) {
				if chartpath, _, err = chartdownloader.DownloadTo(p.ChartAddress, chartversion, ConfigDir); err != nil {
					return err
				}
			}

		} else if p.ChartLocalFilename != "" {

			if !strings.HasSuffix(p.ChartLocalFilename, ".tgz") {
				return fmt.Errorf("ChartLocalFilename==%v is not a .tgz file", p.ChartLocalFilename)
			}

			if mm, err := filepath.Glob(path.Join(ConfigDir, p.ChartLocalFilename)); err != nil {
				return fmt.Errorf("Glob ConfigDir==%v ChartLocalFilename==%v: %s", ConfigDir, p.ChartLocalFilename, err)
			} else if len(mm) == 0 {
				return fmt.Errorf("Glob ConfigDir==%v ChartLocalFilename==%v files not found", ConfigDir, p.ChartLocalFilename)
			} else {
				sort.Sort(sort.Reverse(sort.StringSlice(mm)))
				chartpath = mm[0]
			}

		} else {

			return fmt.Errorf("no ChartRepoAddress, ChartAddress, ChartLocalFilename")

		}

		// https://pkg.go.dev/helm.sh/helm/v3/pkg/chart/loader#Load
		chartfull, err = helmloader.Load(chartpath)
		if err != nil {
			return fmt.Errorf("helmloader.Load %v: %w", chartpath, err)
		} else if chartfull == nil {
			return fmt.Errorf("loaded chart is nil")
		}

		// https://pkg.go.dev/helm.sh/helm/v3@v3.16.3/pkg/chart#Metadata
		chartversion = chartfull.Metadata.Version

		//
		// FILL IMAGES VALUES
		//

		p.ImagesValues[p.ChartVersionKey] = chartversion

		drlatestyamlhelmvalues := make(map[string]interface{})
		for _, m := range []map[string]interface{}{chartfull.Values, p.Values, p.EnvValues} {
			for k, v := range m {
				drlatestyamlhelmvalues[k] = v
			}
		}
		err = drlatestyaml(drlatestyamlhelmvalues, Config.DrLatestYaml, &p.ImagesValues)
		if err != nil {
			return fmt.Errorf("drlatestyaml %s: %w", p.Name, err)
		}

		p.ImagesValuesList, p.ImagesValuesText, err = ImagesValuesToList(p.ImagesValues)

		if DEBUG {
			p.log("DEBUG ImagesValues==%#v", p.ImagesValues)
		}

		//
		// UPDATE TIMESTAMP
		//

		if err := os.Chtimes(updatetimestampfilename, timenow, timenow); os.IsNotExist(err) {
			if f, err := os.Create(updatetimestampfilename); err == nil {
				f.Close()
			} else {
				p.log("ERROR create timestamp file: %v", err)
			}
		}

		//
		// LATEST VALUES HASH
		//

		var allvaluestext string
		if len(p.LocalValues) == 0 {
			allvaluestext = p.GlobalValuesText + p.ValuesText + p.EnvValuesText + p.ImagesValuesText
		} else {
			allvaluestext = fmt.Sprintf("%#v", p.LocalValues) + p.ImagesValuesText
		}
		p.ValuesHash = fmt.Sprintf("%x", sha256.Sum256([]byte(allvaluestext)))[:HashLength]

		//
		// READ DEPLOYED HASH
		//

		var ValuesDeployedHash string
		if err := GetValuesText(p.ValuesDeployedHashFilename(), &ValuesDeployedHash, true); err != nil {

			p.log("ERROR GetValuesText: %s", err)
			continue

		}

		//
		// COMPARE LATEST HASH VS DEPLOYED HASH
		//

		if p.ValuesHash == ValuesDeployedHash {

			if DEBUG {
				p.log("DEBUG ValuesHash==ValuesDeployedHash")
			}
			time.Sleep(PackagesSleepDuration)
			continue

		}

		//
		// READ REPORTED HASH
		//

		var ValuesReportedHash string
		if err := GetValuesText(p.ValuesReportedHashFilename(), &ValuesReportedHash, true); err != nil {
			p.log("ERROR GetValuesText: %v", err)
		}

		if DEBUG {
			p.log("DEBUG ValuesHash==%v ValuesReportedHash==%v ValuesDeployedHash==%v PermitHash==%v ", p.ValuesHash, ValuesReportedHash, ValuesDeployedHash, PermitHash)
		}

		//
		// READ DEPLOYED VALUES
		//

		var DeployedGlobalValuesText string
		var DeployedValuesText string
		var DeployedEnvValuesText string
		var DeployedImagesValuesText string

		if len(p.LocalValues) == 0 {

			if err := GetValuesTextFile(path.Join(p.FullName(), p.GlobalValuesFilename()), &DeployedGlobalValuesText, false); err != nil {
				p.log("ERROR GetValuesTextFile: %v", err)
			}

			if err := GetValuesTextFile(path.Join(p.FullName(), p.ValuesFilename()), &DeployedValuesText, false); err != nil {
				p.log("ERROR GetValuesTextFile: %v", err)
			}

			if err := GetValuesTextFile(path.Join(p.FullName(), p.EnvValuesFilename()), &DeployedEnvValuesText, false); err != nil {
				p.log("ERROR GetValuesTextFile: %v", err)
			}

		}

		if err := GetValuesTextFile(path.Join(p.FullName(), p.ImagesValuesFilename()), &DeployedImagesValuesText, false); err != nil {
			p.log("ERROR GetValuesTextFile: %v", err)
		}

		//
		// COMPARE LATEST VS DEPLOYED
		//

		globalvaluesdiff := false
		valuesdiff := false
		envvaluesdiff := false
		imagesvaluesdiff := ""

		if p.GlobalValuesText != DeployedGlobalValuesText {
			globalvaluesdiff = true
		}

		if p.ValuesText != DeployedValuesText {
			valuesdiff = true
		}

		if p.EnvValuesText != DeployedEnvValuesText {
			envvaluesdiff = true
		}

		if p.ImagesValuesText != DeployedImagesValuesText {

			DeployedImagesValuesMap := make(map[string]string)
			yd := yaml.NewDecoder(strings.NewReader(DeployedImagesValuesText))
			for {
				if err := yd.Decode(&DeployedImagesValuesMap); err != nil {
					if err != io.EOF {
						return fmt.Errorf("yaml Decode %w", err)
					}
					break
				}
			}

			iv1, iv2 := DeployedImagesValuesMap, p.ImagesValues
			for name, v1 := range iv1 {
				if v2, ok := iv2[name]; ok {
					if v2 != v1 {
						imagesvaluesdiff += fmt.Sprintf("%s: %#v=>%#v "+NL, name, v1, v2)
					}
				} else {
					imagesvaluesdiff += fmt.Sprintf("-- %s: %#v "+NL, name, v1)
				}
			}
			for name, v2 := range iv2 {
				if _, ok := iv1[name]; !ok {
					imagesvaluesdiff += fmt.Sprintf("++ %s: %#v "+NL, name, v2)
				}
			}

			if DEBUG {
				p.log("DEBUG ImagesValues diff: "+NL+"%v", imagesvaluesdiff)
			}

		}

		//
		// CHECK IF DEPLOY IS ALLOWED NOW
		//

		deploynow := false

		if p.AlwaysForceNow != nil && *p.AlwaysForceNow {
			deploynow = true
		}
		if slices.Contains(p.AllowedHoursList, timenowhour) {
			deploynow = true
		}
		if PermitHash == p.ValuesHash {
			deploynow = true
		}

		//
		// PREPARE TELEGRAM MESSAGE
		//

		var tgmsg string
		var tgmsgid int64
		var tgerr error

		tgmsg = tg.Bold(fmt.Sprintf("%s %s UPDATE", strings.ToUpper(p.ChartName), strings.ToUpper(p.EnvName))) + NL + NL
		if globalvaluesdiff {
			tgmsg += tg.Code(p.GlobalValuesFilename()) + " changed" + NL + NL
		}
		if valuesdiff {
			tgmsg += tg.Code(p.ValuesFilename()) + " changed" + NL + NL
		}
		if envvaluesdiff {
			tgmsg += tg.Code(p.EnvValuesFilename()) + " changed" + NL + NL
		}
		if imagesvaluesdiff != "" {
			tgmsg += tg.Code(p.ImagesValuesFilename()) + " diff:" + NL + tg.Pre(imagesvaluesdiff) + NL + NL
		}

		if !deploynow {

			if p.ValuesHash != ValuesReportedHash {

				if VERBOSE {
					p.log("reporting pending update")
				}

				tgmsg += tg.Bold("NOT UPDATING NOW") + tg.Esc("; update will start ") + tg.Bold("in the next allowed time window") + NL + NL
				tgmsg += tg.Esc("TO FORCE START THIS UPDATE NOW REPLY TO THIS MESSAGE WITH TEXT \"") + tg.Code("NOW") + tg.Esc("\" (UPPERCASE)") + NL + NL
				if tgmsgid, tgerr = p.tglog(tgmsg, 0, 0); tgerr != nil {
					p.log("ERROR tglog: %v", tgerr)
				}

				//
				// WRITE REPORTED HASH
				//

				if err := PutValuesText(p.ValuesReportedHashFilename(), p.ValuesHash); err != nil {
					return fmt.Errorf("PutValuesText: %w", err)
				}

			}

			time.Sleep(PackagesSleepDuration)
			continue

		}

		if VERBOSE {
			p.log("installing update")
		}

		if p.UpdateDelayDuration > 0 {

			tgmsg += tg.Bold(fmt.Sprintf("STARTING IN %v", p.UpdateDelayDuration)) + NL + NL

			if tgmsgid, tgerr = p.tglog(tgmsg, 0, tgmsgid); tgerr != nil {
				p.log("ERROR tglog: %v", tgerr)
			}

			if VERBOSE {
				p.log("sleeping %v", p.UpdateDelayDuration)
			}
			time.Sleep(p.UpdateDelayDuration)

		}

		//
		// DEPLOY
		//

		if VERBOSE {
			p.log("starting update")
		}

		tgmsg += tg.Bold("STARTED") + NL + NL

		if tgmsgid, tgerr = p.tglog(tgmsg, 0, tgmsgid); tgerr != nil {
			p.log("ERROR tglog: %v", tgerr)
		}

		// PREPARE VALUES

		values := make(map[string]interface{})

		if *p.GlobalValuesDisabled {
			delete(p.ImagesValues, p.ChartVersionKey)
		}
		helmchartutil.MergeTables(values, p.ImagesValues)

		if len(p.LocalValues) > 0 {
			helmchartutil.MergeTables(values, p.LocalValues)
		} else {
			helmchartutil.MergeTables(values, p.EnvValues)
			helmchartutil.MergeTables(values, p.Values)
			p.log("DEBUG GlobalValuesDisabled==%+v", *p.GlobalValuesDisabled)
			if !*p.GlobalValuesDisabled {
				helmchartutil.MergeTables(values, p.GlobalValues)
			}
		}

		helmchartutil.MergeTables(values, chartfull.Values)

		// TODO make sure values are correctly merged
		if DEBUG {
			//p.log("DEBUG values==%+v", values)
		}

		// TODO objects get created in helmbot namespace if namespace not specified in the yaml manifest

		helmenvsettings := helmcli.New()
		helmenvsettings.SetNamespace(p.Namespace)
		helmactioncfg := new(helmaction.Configuration)
		if err := helmactioncfg.Init(helmenvsettings.RESTClientGetter(), p.Namespace, "", p.log); err != nil {
			tgmsg += tg.Bold("INTERNAL ERROR") + NL + NL
			if tgmsgid, tgerr = p.tglog(tgmsg, 0, tgmsgid); tgerr != nil {
				p.log("ERROR tglog: %v", tgerr)
			}
			return err
		}

		isinstalled := false
		for _, r := range installedreleases {
			if r.Name == p.Name && r.Namespace == p.Namespace {
				isinstalled = true
			}
		}

		var release *helmrelease.Release

		if isinstalled {

			// https://pkg.go.dev/helm.sh/helm/v3/pkg/action#Upgrade
			helmupgrade := helmaction.NewUpgrade(helmactioncfg)
			helmupgrade.DryRun = *p.DryRun
			helmupgrade.Namespace = p.Namespace

			release, err = helmupgrade.Run(
				p.Name,
				chartfull,
				values,
			)

		} else {

			// https://pkg.go.dev/helm.sh/helm/v3/pkg/action#Install
			helminstall := helmaction.NewInstall(helmactioncfg)
			helminstall.DryRun = *p.DryRun
			helminstall.CreateNamespace = true
			helminstall.Namespace = p.Namespace
			helminstall.ReleaseName = p.Name

			release, err = helminstall.Run(
				chartfull,
				values,
			)

		}

		if err != nil {

			p.log("ERROR helm Run: %v", err)

			tgmsg += tg.Bold("ERROR") + NL + NL + tg.Pre(fmt.Sprintf("%v", err)) + NL + NL

			if _, tgerr = p.tglog(tgmsg, 0, tgmsgid); tgerr != nil {
				p.log("ERROR tglog: %v", tgerr)
			}

			return err

		}

		// TODO delay helmbot self-update for saving deployed values and hash

		if VERBOSE {
			p.log("installed release Name==%v Namespace==%v Info.Status==%v HashId==%v", release.Name, release.Namespace, release.Info.Status, p.HashId())
		}

		tgmsg += tg.Pre(fmt.Sprintf(
			"NAME: %v"+NL+
				"NAMESPACE: %v"+NL+
				"STATUS: %v",
			release.Name,
			release.Namespace,
			release.Info.Status,
		)) + NL + NL

		if release.Info.Notes != "" {
			notes := strings.TrimSpace(release.Info.Notes)
			if len(notes) > 2000 {
				notes = notes[:1000] + NL + NL + "---cut-cut-cut---" + NL + NL + notes[len(notes)-1000:]
			}
			tgmsg += tg.Pre(notes) + NL + NL
		}

		// TODO TgBossUserIds
		if tgmsgid, tgerr = p.tglog(tgmsg, 0, tgmsgid); tgerr != nil {
			p.log("ERROR tglog: %v", tgerr)
		}

		//
		// WRITE DEPLOYED HASH
		//

		if err := PutValuesText(p.ValuesDeployedHashFilename(), p.ValuesHash); err != nil {
			tgmsg += tg.Bold("INTERNAL ERROR") + NL + NL
			if tgmsgid, tgerr = p.tglog(tgmsg, 0, tgmsgid); tgerr != nil {
				p.log("ERROR tglog: %v", tgerr)
			}
			return fmt.Errorf("PutValuesText: %w", err)
		}

		//
		// DELETE PERMIT HASH AND REPORTED HASH
		//

		if err := DeleteValues(p.ValuesPermitHashFilename()); err != nil {
			if VERBOSE {
				p.log("WARNING DeleteValues: %v", err)
			}
		}
		if err := DeleteValues(p.ValuesReportedHashFilename()); err != nil {
			if VERBOSE {
				p.log("WARNING DeleteValues: %v", err)
			}
		}

		//
		// WRITE DEPLOYED VALUES
		//

		if err := p.WriteDeployedValues(); err != nil {
			p.log("ERROR WriteDeployedValues: %v", err)
			tgmsg += tg.Bold("INTERNAL ERROR") + NL + NL
			if tgmsgid, tgerr = p.tglog(tgmsg, 0, tgmsgid); tgerr != nil {
				p.log("ERROR tglog: %v", tgerr)
			}
			return err
		}

		tgmsg += tg.Bold(fmt.Sprintf("%s %s UPDATE FINISHED", strings.ToUpper(p.ChartName), strings.ToUpper(p.EnvName))) + NL + NL

		if tgmsgid, tgerr = p.tglog(tgmsg, 0, tgmsgid); tgerr != nil {
			p.log("ERROR tglog: %v", tgerr)
		}

		//
		// DEPLOY FINISHED
		//

		time.Sleep(PackagesSleepDuration)
		continue

	}

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

		if s.UpdateInterval != nil && *s.UpdateInterval != "" {
			s.UpdateIntervalDuration, err = time.ParseDuration(*s.UpdateInterval)
			if err != nil {
				return nil, err
			}
		}

		if s.UpdateDelay != nil && *s.UpdateDelay != "" {
			s.UpdateDelayDuration, err = time.ParseDuration(*s.UpdateDelay)
			if err != nil {
				return nil, err
			}
		}

		if s.GlobalValuesDisabled == nil {
			s.GlobalValuesDisabled = &FALSE
		}

		if s.DryRun == nil {
			s.DryRun = &FALSE
		}

		for _, p := range s.Packages {

			if p.ChartName == "" {
				return nil, fmt.Errorf("package ChartName is empty")
			}

			if p.EnvName == "" {
				p.EnvName = s.EnvName
			}
			if p.EnvName == "" {
				return nil, fmt.Errorf("package EnvName is empty")
			}

			p.Name = fmt.Sprintf("%s-%s", p.ChartName, p.EnvName)

			if p.Namespace == "" {
				if s.Namespace != "" {
					p.Namespace = s.Namespace
				} else {
					p.Namespace = fmt.Sprintf("%s-%s", p.ChartName, p.EnvName)
				}
			}

			p.ServerHostname = &s.ServerHostname

			if p.AllowedHours == nil {
				p.AllowedHours = s.AllowedHours
				p.AllowedHoursList = s.AllowedHoursList
			} else {
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

			if p.UpdateInterval == nil {
				p.UpdateInterval = s.UpdateInterval
				p.UpdateIntervalDuration = s.UpdateIntervalDuration
			} else {
				p.UpdateIntervalDuration, err = time.ParseDuration(*p.UpdateInterval)
				if err != nil {
					return nil, err
				}
			}

			if p.UpdateDelay == nil {
				p.UpdateDelay = s.UpdateDelay
				p.UpdateDelayDuration = s.UpdateDelayDuration
			} else {
				p.UpdateDelayDuration, err = time.ParseDuration(*p.UpdateDelay)
				if err != nil {
					return nil, err
				}
			}

			if p.ChartVersionKey == "" {
				ww := strings.Split(p.ChartName, "-")
				for i := range ww {
					ww[i] = textcases.Title(textlanguage.English, textcases.NoLower).String(ww[i])
				}
				p.ChartVersionKey = "HelmChartVersion" + strings.Join(ww, "")
			}

			if p.TgChatId == nil {
				p.TgChatId = s.TgChatId
			}
			if p.TgMentions == nil {
				p.TgMentions = s.TgMentions
			}

			if p.DryRun == nil {
				p.DryRun = s.DryRun
			}

			if p.GlobalValuesDisabled == nil {
				p.GlobalValuesDisabled = s.GlobalValuesDisabled
			}

			p.GlobalValues = make(map[string]interface{})
			p.Values = make(map[string]interface{})
			p.EnvValues = make(map[string]interface{})
			p.ImagesValues = make(map[string]interface{})

			packages = append(packages, p)

		}

	}

	return packages, nil
}

func GetValuesText(name string, valuestext *string, notexistok bool) (err error) {
	if ValuesMinioUrlHost != "" {
		return GetValuesTextMinio(name, valuestext, notexistok)
	}
	return GetValuesTextFile(name, valuestext, notexistok)
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

func DeleteValues(name string) (err error) {
	if ValuesMinioUrlHost != "" {
		return DeleteValuesMinio(name)
	}
	return DeleteValuesFile(name)
}

func GetValuesTextFile(name string, valuestext *string, notexistok bool) (err error) {
	filepath := path.Join(ConfigDir, name)

	bb, err := os.ReadFile(filepath)
	if os.IsNotExist(err) && !notexistok {
		return fmt.Errorf("GetValuesTextFile %s: does not exist", name)
	} else if os.IsNotExist(err) && notexistok {
	} else if err != nil {
		return fmt.Errorf("GetValuesTextFile %s: %w", name, err)
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

	err = GetValuesTextFile(name, valuestext, false)
	if err != nil {
		return fmt.Errorf("GetValuesFile %s: %w", name, err)
	}

	d := yaml.NewDecoder(strings.NewReader(*valuestext))
	err = d.Decode(values)
	if err != nil {
		return fmt.Errorf("GetValuesFile %s: %w", name, err)
	}

	return nil
}

func PutValuesTextFile(name string, valuestext string) (err error) {
	filepath := path.Join(ConfigDir, name)

	err = os.WriteFile(filepath, []byte(valuestext), 0644)
	if err != nil {
		return fmt.Errorf("PutValuesTextFile %s: %w", name, err)
	}
	return nil
}

func DeleteValuesFile(name string) (err error) {
	if DEBUG {
		log("DEBUG DeleteValuesFile %v", name)
	}
	//filepath := path.Join(ConfigDir, name)
	// TODO delete filepath
	return nil
}

type PackageConfig struct {
	Name string `yaml:"Name"`

	ChartName string `yaml:"ChartName"`
	EnvName   string `yaml:"EnvName"`

	Namespace string `yaml:"Namespace,omitempty"`

	ChartVersion    string `yaml:"ChartVersion"`
	ChartVersionKey string `yaml:"ChartVersionKey"`

	ChartLocalFilename string `yaml:"ChartLocalFilename"`

	ChartAddress string `yaml:"ChartAddress"`

	ChartRepo struct {
		Address  string `yaml:"Address"`
		Username string `yaml:"Username"`
		Password string `yaml:"Password"`
	} `yaml:"ChartRepo"`

	ServerHostname *string `yaml:"ServerHostname,omitempty"`

	TgChatId   *int64  `yaml:"TgChatId,omitempty"`
	TgMentions *string `yaml:"TgMentions,omitempty"`

	AlwaysForceNow *bool `yaml:"AlwaysForceNow,omitempty"`
	ForceNow       bool  `yaml:"ForceNow"`

	UpdateInterval *string `yaml:"UpdateInterval,omitempty"`
	UpdateDelay    *string `yaml:"UpdateDelay,omitempty"`

	Timezone     *string `yaml:"Timezone,omitempty"`
	AllowedHours *string `yaml:"AllowedHours,omitempty"`

	LocalValues map[string]interface{} `yaml:"LocalValues,omitempty"`

	UpdateIntervalDuration time.Duration
	UpdateDelayDuration    time.Duration
	UpdateTimestamp        time.Time

	TimezoneLocation *time.Location
	AllowedHoursList []string

	GlobalValuesDisabled *bool `yaml:"GlobalValuesDisabled"`

	GlobalValuesText string
	ValuesText       string
	EnvValuesText    string
	ImagesValuesText string

	GlobalValues     map[string]interface{}
	Values           map[string]interface{}
	EnvValues        map[string]interface{}
	ImagesValuesList []map[string]interface{}
	ImagesValues     map[string]interface{}

	ValuesHash string

	DryRun *bool `yaml:"DryRun,omitempty"`
}

func (p *PackageConfig) FullName() string {
	return fmt.Sprintf("%s.%s", p.ChartName, p.EnvName)
}

func (p *PackageConfig) GlobalValuesFilename() string {
	return "global.values.yaml"
}
func (p *PackageConfig) ValuesFilename() string {
	return fmt.Sprintf("%s.values.yaml", p.ChartName)
}
func (p *PackageConfig) EnvValuesFilename() string {
	return fmt.Sprintf("%s.values.yaml", p.FullName())
}
func (p *PackageConfig) ImagesValuesFilename() string {
	return fmt.Sprintf("%s.images.values.yaml", p.FullName())
}

func (p *PackageConfig) ValuesReportedHashFilename() string {
	return fmt.Sprintf("%s.values.reported.hash.text", p.FullName())
}
func (p *PackageConfig) ValuesDeployedHashFilename() string {
	return fmt.Sprintf("%s.values.deployed.hash.text", p.FullName())
}
func (p *PackageConfig) ValuesPermitHashFilename() string {
	return fmt.Sprintf("%s.values.permit.hash.text", p.FullName())
}

func (p *PackageConfig) PausedFilename() string {
	return fmt.Sprintf("%s.paused", p.FullName())
}
func (p *PackageConfig) UpdateTimestampFilename() string {
	return fmt.Sprintf("%s.update.timestamp", p.FullName())
}

func (p *PackageConfig) HashId() string {
	return fmt.Sprintf("#%s#%s#%s", p.ChartName, p.EnvName, p.ValuesHash)
}

func (p *PackageConfig) WriteDeployedValues() error {

	if err := os.RemoveAll(path.Join(ConfigDir, p.FullName())); err != nil {
		return fmt.Errorf("RemoveAll: %w", err)
	}
	if err := os.MkdirAll(path.Join(ConfigDir, p.FullName()), 0700); err != nil {
		return fmt.Errorf("MkdirAll: %w", err)
	}

	if len(p.LocalValues) == 0 {

		if err := PutValuesTextFile(path.Join(p.FullName(), p.GlobalValuesFilename()), p.GlobalValuesText); err != nil {
			return fmt.Errorf("PutValuesTextFile: %w", err)
		}
		if err := PutValuesTextFile(path.Join(p.FullName(), p.ValuesFilename()), p.ValuesText); err != nil {
			return fmt.Errorf("PutValuesTextFile: %w", err)
		}
		if err := PutValuesTextFile(path.Join(p.FullName(), p.EnvValuesFilename()), p.EnvValuesText); err != nil {
			return fmt.Errorf("PutValuesTextFile: %w", err)
		}

	}

	if err := PutValuesTextFile(path.Join(p.FullName(), p.ImagesValuesFilename()), p.ImagesValuesText); err != nil {
		return fmt.Errorf("PutValuesTextFile: %w", err)
	}

	return nil
}

type ServerConfig struct {
	ServerHostname string `yaml:"ServerHostname"`

	EnvName string `yaml:"EnvName"`

	Namespace string `yaml:"Namespace,omitempty"`

	AlwaysForceNow *bool `yaml:"AlwaysForceNow,omitempty"`

	UpdateInterval *string `yaml:"UpdateInterval,omitempty"`
	UpdateDelay    *string `yaml:"UpdateDelay,omitempty"`

	UpdateIntervalDuration time.Duration
	UpdateDelayDuration    time.Duration

	TgChatId   *int64  `yaml:"TgChatId,omitempty"`
	TgMentions *string `yaml:"TgMentions,omitempty"`

	Packages []PackageConfig `yaml:"Packages"`

	Timezone     *string `yaml:"Timezone,omitempty"`
	AllowedHours *string `yaml:"AllowedHours,omitempty"`

	TimezoneLocation *time.Location
	AllowedHoursList []string

	GlobalValuesDisabled *bool `yaml:"GlobalValuesDisabled"`

	DryRun *bool `yaml:"DryRun,omitempty"`
}

type HelmbotConfig struct {
	DrLatestYaml []DrLatestYamlItem `yaml:"DrLatestYaml"`
	Servers      []ServerConfig     `yaml:"Servers"`
}

func ts() string {
	tnow := time.Now().In(LogTimeLocation)
	return fmt.Sprintf(
		"%d%02d%02d:%02d%02d%s",
		tnow.Year()%1000, tnow.Month(), tnow.Day(),
		tnow.Hour(), tnow.Minute(), LogTimeZone,
	)
}

func log(msg string, args ...interface{}) {
	logmsg := fmt.Sprintf(ts()+" "+msg, args...) + NL
	if TgToken != "" {
		logmsg = strings.ReplaceAll(logmsg, TgToken, "{{TgToken}}")
	}
	if TgWebhookToken != "" {
		logmsg = strings.ReplaceAll(logmsg, TgWebhookToken, "{{TgWebhookToken}}")
	}

	fmt.Fprint(os.Stderr, logmsg)
}

func dirExists(path string) bool {
	s, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return err == nil && s.IsDir()
}

func fileExists(path string) bool {
	s, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return err == nil && s.Mode().IsRegular()
}

// get/put values file from/to a minio storage
// https://gist.github.com/gabo89/5e3e316bd4be0fb99369eac512a66537
// https://stackoverflow.com/questions/72047783/how-do-i-download-files-from-a-minio-s3-bucket-using-curl
func MinioNewRequest(method, name string, payload []byte) (req *http.Request, err error) {
	req, err = http.NewRequest(method, ValuesMinioUrl+name, bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "helmbot")
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Host", ValuesMinioUrl)
	req.Header.Set("Date", time.Now().UTC().Format(time.RFC1123Z))

	hdrauthsig := method + NL + NL + req.Header.Get("Content-Type") + NL + req.Header.Get("Date") + NL + ValuesMinioUrlPath + name
	hdrauthsighmac := hmac.New(sha1.New, []byte(ValuesMinioPassword))
	hdrauthsighmac.Write([]byte(hdrauthsig))
	hdrauthsig = base64.StdEncoding.EncodeToString(hdrauthsighmac.Sum(nil))
	req.Header.Set("Authorization", fmt.Sprintf("AWS %s:%s", ValuesMinioUsername, hdrauthsig))

	return req, nil
}

func GetValuesTextMinio(name string, valuestext *string, notexistok bool) (err error) {
	var respbody string

	if req, err := MinioNewRequest(http.MethodGet, name, nil); err != nil {
		return fmt.Errorf("GetValuesTextMinio %s: %w", name, err)
	} else if resp, err := http.DefaultClient.Do(req); err != nil {
		return fmt.Errorf("GetValuesTextMinio %s: %w", name, err)
	} else if resp.StatusCode == 404 && !notexistok {
		return fmt.Errorf("GetValuesTextMinio %s: minio server response status %s", name, resp.Status)
	} else if resp.StatusCode == 404 && notexistok {
		respbody = ""
	} else if resp.StatusCode != 200 {
		return fmt.Errorf("GetValuesTextMinio %s: minio server response status %s", name, resp.Status)
	} else if bb, err := ioutil.ReadAll(resp.Body); err != nil {
		return fmt.Errorf("GetValuesTextMinio %s: %w", name, err)
	} else {
		respbody = string(bb)
	}

	*valuestext = respbody

	return nil
}

func GetValuesMinio(name string, valuestext *string, values interface{}) (err error) {
	if valuestext == nil {
		var valuestext1 string
		valuestext = &valuestext1
	}

	err = GetValuesTextMinio(name, valuestext, false)
	if err != nil {
		return fmt.Errorf("GetValuesMinio %s: %w", name, err)
	}

	d := yaml.NewDecoder(strings.NewReader(*valuestext))
	err = d.Decode(values)
	if err != nil {
		return fmt.Errorf("GetValuesMinio %s: %w", name, err)
	}

	return nil
}

func PutValuesTextMinio(name string, valuestext string) (err error) {
	if DEBUG {
		log("DEBUG PutValuesTextMinio %s [len==%d]: %s", name, len(valuestext), strings.ReplaceAll((valuestext), NL, " <nl> "))
	}

	if req, err := MinioNewRequest(http.MethodPut, name, []byte(valuestext)); err != nil {
		return fmt.Errorf("PutValuesTextMinio %s: %w", name, err)
	} else if resp, err := http.DefaultClient.Do(req); err != nil {
		return fmt.Errorf("PutValuesTextMinio %s: %w", name, err)
	} else if resp.StatusCode != 200 {
		return fmt.Errorf("PutValuesTextMinio %s: minio server response status %s", name, resp.Status)
	}

	return nil
}

func DeleteValuesMinio(name string) (err error) {
	if DEBUG {
		log("DEBUG DeleteValuesMinio %v", name)
	}

	if req, err := MinioNewRequest(http.MethodDelete, name, nil); err != nil {
		return fmt.Errorf("DeleteValuesMinio %v: %w", name, err)
	} else if resp, err := http.DefaultClient.Do(req); err != nil {
		return fmt.Errorf("DeleteValuesMinio %v: %w", name, err)
	} else if resp.StatusCode != 200 {
		return fmt.Errorf("DeleteValuesMinio %v: minio server response status %s", name, resp.Status)
	}

	return nil
}

type DrLatestYamlItem struct {
	KeyPrefix        string `yaml:"KeyPrefix"`
	KeyPrefixReplace string `yaml:"KeyPrefixReplace"`
	RegistryUsername string `yaml:"RegistryUsername"`
	RegistryPassword string `yaml:"RegistryPassword"`
}

type DrVersions []string

func (vv DrVersions) Len() int {
	return len(vv)
}

func (vv DrVersions) Less(i, j int) bool {
	v1, v2 := vv[i], vv[j]
	v1s := strings.Split(v1, ".")
	v2s := strings.Split(v2, ".")
	if len(v1s) < len(v2s) {
		return true
	} else if len(v1s) > len(v2s) {
		return false
	}
	for e := 0; e < len(v1s); e++ {
		d1, _ := strconv.Atoi(v1s[e])
		d2, _ := strconv.Atoi(v2s[e])
		if d1 < d2 {
			return true
		} else if d1 > d2 {
			return false
		}
	}
	return false
}

func (vv DrVersions) Swap(i, j int) {
	vv[i], vv[j] = vv[j], vv[i]
}

func drlatestyaml(helmvalues map[string]interface{}, drlatestyamlitems []DrLatestYamlItem, imagesvalues *map[string]interface{}) (err error) {
	for helmvalueskey, helmvaluesvalue := range helmvalues {
		for _, e := range drlatestyamlitems {
			if strings.HasPrefix(helmvalueskey, e.KeyPrefix) {

				imagename := helmvalueskey
				imagenamereplace := e.KeyPrefixReplace + strings.TrimPrefix(imagename, e.KeyPrefix)

				if v, ok := helmvalues[imagenamereplace]; ok && v != "" {
					continue
				}

				imageurl := helmvaluesvalue.(string)

				if !strings.HasPrefix(imageurl, "https://") && !strings.HasPrefix(imageurl, "http://") {
					imageurl = fmt.Sprintf("https://%s", imageurl)
				}

				var u *url.URL
				if u, err = url.Parse(imageurl); err != nil {
					return fmt.Errorf("url.Parse %s %v: %w", imagename, imageurl, err)
				}

				RegistryUrl := fmt.Sprintf("%s://%s", u.Scheme, u.Host)
				RegistryRepository := u.Path

				if DEBUG {
					//log("DEBUG drlatestyaml registry %s %s", RegistryUrl, RegistryRepository)
				}

				r := dregistry.NewInsecure(RegistryUrl, e.RegistryUsername, e.RegistryPassword)
				r.Logf = dregistry.Quiet

				imagetags, err := r.Tags(RegistryRepository)
				if err != nil {
					return fmt.Errorf("registry.Tags %s %v: %w", imagename, imageurl, err)
				}

				sort.Sort(sort.Reverse(DrVersions(imagetags)))

				imagetag := ""

				if len(imagetags) > 0 {
					imagetag = imagetags[0]
				} else {
					imagetag = "latest"
				}

				(*imagesvalues)[imagenamereplace] = imagetag

			}
		}
	}

	return nil
}

func ImagesValuesToList(imagesvaluesmap map[string]interface{}) (imagesvalueslist []map[string]interface{}, imagesvaluestext string, err error) {
	imagesvalueslist = make([]map[string]interface{}, 0)
	for k, v := range imagesvaluesmap {
		imagesvalueslist = append(imagesvalueslist, map[string]interface{}{k: v})
	}
	sort.Slice(
		imagesvalueslist,
		func(i, j int) bool {
			for ik := range imagesvalueslist[i] {
				for jk := range imagesvalueslist[j] {
					return ik < jk
				}
			}
			return false
		},
	)

	for _, iv := range imagesvalueslist {
		if bb, err := yaml.Marshal(iv); err != nil {
			return nil, "", fmt.Errorf("yaml.Encoder: %w", err)
		} else {
			imagesvaluestext += string(bb)
		}
	}

	return imagesvalueslist, imagesvaluestext, nil
}

func TgSetWebhook(url string, allowedupdates []string, secrettoken string) error {
	if DEBUG {
		log("DEBUG TgSetWebhook url==%s allowedupdates==%s secrettoken==%s", url, allowedupdates, secrettoken)
	}

	swreq := TgSetWebhookRequest{
		Url:            url,
		MaxConnections: TgWebhookMaxConnections,
		AllowedUpdates: allowedupdates,
		SecretToken:    secrettoken,
	}
	swreqjs, err := json.Marshal(swreq)
	if err != nil {
		return err
	}
	swreqjsBuffer := bytes.NewBuffer(swreqjs)

	var resp *http.Response
	tgapiurl := fmt.Sprintf("https://api.telegram.org/bot%s/setWebhook", TgToken)
	resp, err = http.Post(
		tgapiurl,
		"application/json",
		swreqjsBuffer,
	)
	if err != nil {
		return fmt.Errorf("url==%v data==%v error: %v", tgapiurl, string(swreqjs), err)
	}

	var swresp TgSetWebhookResponse
	var swrespbody []byte
	swrespbody, err = io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("io.ReadAll: %w", err)
	}
	err = json.NewDecoder(bytes.NewBuffer(swrespbody)).Decode(&swresp)
	if err != nil {
		return fmt.Errorf("json.Decoder.Decode: %w", err)
	}
	if !swresp.OK || !swresp.Result {
		return fmt.Errorf("url==%v data==%v api response not ok: %+v", tgapiurl, string(swreqjs), swresp)
	}

	return nil
}

type TgSetWebhookRequest struct {
	Url            string   `json:"url"`
	MaxConnections int64    `json:"max_connections"`
	AllowedUpdates []string `json:"allowed_updates"`
	SecretToken    string   `json:"secret_token,omitempty"`
}

type TgSetWebhookResponse struct {
	OK          bool   `json:"ok"`
	Description string `json:"description"`
	Result      bool   `json:"result"`
}

func (p *PackageConfig) log(msg string, args ...interface{}) {
	log(SPAC+p.Name+" "+msg, args...)
}

func (p *PackageConfig) tglog(msg string, replyid, editid int64) (msgid int64, err error) {
	chatid := TgBossUserIds[0]
	if p.TgChatId != nil {
		chatid = *p.TgChatId
	}
	msg += tg.Code(p.HashId())
	return tglog(msg, chatid, replyid, editid)
}

func tglog(msg string, chatid, replyid, editid int64) (msgid int64, err error) {
	// TODO proper formatting escaping

	req := tg.SendMessageRequest{
		ChatId:              fmt.Sprintf("%d", chatid),
		MessageId:           editid,
		ReplyToMessageId:    replyid,
		Text:                msg,
		ParseMode:           TgParseMode,
		DisableNotification: TgDisableNotification,
	}

	var reqjs []byte
	reqjs, err = json.Marshal(req)
	if err != nil {
		return 0, err
	}
	reqjsBuffer := bytes.NewBuffer(reqjs)

	tgurl := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", TgToken)
	if req.MessageId != 0 {
		tgurl = fmt.Sprintf("https://api.telegram.org/bot%s/editMessageText", TgToken)
	}

	var resp *http.Response
	resp, err = http.Post(
		tgurl,
		"application/json",
		reqjsBuffer,
	)
	if err != nil {
		return 0, fmt.Errorf("url==%v data==%v error: %v", tgurl, string(reqjs), err)
	}

	var tgresp tg.MessageResponse
	err = json.NewDecoder(resp.Body).Decode(&tgresp)
	if err != nil {
		return 0, fmt.Errorf("%v", err)
	}
	if !tgresp.Ok {
		return 0, fmt.Errorf("url==%v data==%v api response not ok: %+v", tgurl, string(reqjs), tgresp)
	}

	return tgresp.Result.MessageId, nil
}
