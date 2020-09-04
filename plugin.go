package gsuite_sso

import (
	"github.com/ecletus/plug"
	gsuite_admin_app "github.com/moisespsena-go/gsuite-admin-app"
	"github.com/moisespsena-go/logging"
	path_helpers "github.com/moisespsena-go/path-helpers"
	ect_samlidp "github.com/moisespsena/go-ecletus-samlidp"
)

var (
	pkg = path_helpers.GetCalledDir()
	log = logging.GetOrCreateLogger(pkg)
)

type Plugin struct {
	plug.EventDispatcher

	SamlIdpKey,
	GSuiteAdminAppKey,
	GSuiteSsoIdpKey string
}

func (this *Plugin) RequireOptions() []string {
	return []string{this.SamlIdpKey, this.GSuiteAdminAppKey}
}

func (this *Plugin) ProvideOptions() []string {
	return []string{this.GSuiteSsoIdpKey}
}

func (this *Plugin) ProvidesOptions(options *plug.Options) (err error) {
	idp := options.GetInterface(this.SamlIdpKey).(*ect_samlidp.SamlIDP)
	app := options.GetInterface(this.GSuiteAdminAppKey).(*gsuite_admin_app.App)
	sso := New(idp)
	sso.ConfigureApp(app)
	options.Set(this.GSuiteSsoIdpKey, sso)
	return
}
