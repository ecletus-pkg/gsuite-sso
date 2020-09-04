package gsuite_sso

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"

	saml "github.com/moisespsena-go/xsaml"

	"github.com/ecletus/core"
	"github.com/moisespsena-go/logging"
	"github.com/moisespsena-go/xsaml/samlidp/drivers/gsuite"

	ect_samlidp "github.com/moisespsena/go-ecletus-samlidp"

	gsuite_admin_app "github.com/moisespsena-go/gsuite-admin-app"
	gadmin "google.golang.org/api/admin/directory/v1"
)

// See https://developers.google.com/admin-sdk/admin-settings/auth
const GSuiteAdminSettingsScope = "https://apps-apis.google.com/a/feeds/domain/"

type GSuiteSsoIDP struct {
	IDP                     *ect_samlidp.SamlIDP
	GSuiteMailAddressFinder gsuite.GSuiteMailAddressFinder
}

func New(IDP *ect_samlidp.SamlIDP) *GSuiteSsoIDP {
	sso := &GSuiteSsoIDP{IDP: IDP}
	IDP.Templates.Append(&ect_samlidp.SPTemplate{
		pkg,
		"G Suite",
		func(idp *ect_samlidp.SamlIDP, sp *ect_samlidp.IdpServiceProvider) string {
			return string(gsuite.Metadata("{{.DOMAIN}}"))
		},
		func(sp *ect_samlidp.IdpServiceProvider) {
			sp.Handler = pkg
		},
	})
	IDP.Handlers.Append(&ect_samlidp.SPHandler{
		pkg,
		func(req *saml.IdpAuthnRequest, sp *ect_samlidp.IdpServiceProvider) (err error) {
			req.AttributesProviders.Add(gsuite.NewGSuiteMailAddressProvider(sso.nameIdFinder()))
			return gsuite.RequestSetup(req, sp.MustEntityDescriptor())
		},
	})
	return sso
}

func (this *GSuiteSsoIDP) ConfigureApp(app *gsuite_admin_app.App) {
	app.ScopeAppender(this.AppScopeAppender)
	app.SetupHandler(this.AppSetupHandler)
}

func (this *GSuiteSsoIDP) nameIdFinder() gsuite.GSuiteMailAddressFinder {
	return gsuite.NewGSuiteMailAddressFinder(func(req *saml.IdpAuthnRequest, session *saml.Session, domain string) (email string, err error) {
		if this.GSuiteMailAddressFinder != nil {
			return this.GSuiteMailAddressFinder.Find(req, session, domain)
		}
		return
	})
}

func (this *GSuiteSsoIDP) AppScopeAppender(app *gsuite_admin_app.App, scopes *gsuite_admin_app.Scopes, r *http.Request) (err error) {
	scopes.Add(GSuiteAdminSettingsScope, gadmin.AdminDirectoryUserScope)

	return nil
}

func (this *GSuiteSsoIDP) AppSetupHandler(app *gsuite_admin_app.App, token *gsuite_admin_app.Token, r *http.Request) (err error) {
	log := logging.WithPrefix(log, "["+core.GetSiteFromRequest(r).Name()+"@"+token.Domain+"] setup")
	log.Debugf("start")
	defer func() {
		if err == nil {
			log.Debug("done")
		} else {
			log.Errorf("failed: %v", err.Error())
		}
	}()
	client := app.Crendentials.Client(context.Background(), token.Token)
	defer client.CloseIdleConnections()

	Url := "https://apps-apis.google.com/a/feeds/domain/2.0/" + token.Domain + "/sso/general"

	cfg := `<atom:entry xmlns:atom='http://www.w3.org/2005/Atom' xmlns:apps="http://schemas.google.com/apps/2006'>
<apps:property name='enableSSO' value='true' />
<apps:property name='samlSignonUri' value='`/* + this.IDP.LoginUrl(r) + */+`' />
<apps:property name='samlLogoutUri' value='`/* + this.IDP.LogoutUrl(r)*/ + `' />
<apps:property name='changePasswordUri' value='` + this.IDP.ChangePasswordUrl(r) + `' />
<apps:property name='ssoWhitelist' value='' />
<apps:property name='useDomainSpecificIssuer' value='false'/>
</atom:entry>`
	log.Debug("new settings:", cfg)
	// https://developers.google.com/admin-sdk/admin-settings/#managing_single_sign-on_settings
	req, _ := http.NewRequest(http.MethodPut, Url, bytes.NewBufferString(cfg))
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("update SSO settings failed: %v", err.Error())
	}
	func() {
		defer resp.Body.Close()
		io.Copy(os.Stderr, resp.Body)
		os.Stderr.WriteString("\n")
	}()

	req, _ = http.NewRequest(http.MethodGet, Url, nil)
	resp, err = client.Do(req)
	if err != nil {
		return fmt.Errorf("get SSO settings failed: %v", err.Error())
	}
	func() {
		defer resp.Body.Close()
		io.Copy(os.Stderr, resp.Body)
		os.Stderr.WriteString("\n")
	}()

	return

	Url = "https://apps-apis.google.com/a/feeds/domain/2.0/" + token.Domain + "/sso/signingkey"

	var key = base64.StdEncoding.EncodeToString(this.IDP.Cert.Raw)

	cfg = `<atom:entry xmlns:atom='http://www.w3.org/2005/Atom' xmlns:apps="http://schemas.google.com/apps/2006">
<apps:property name='signingKey' value='` + key + `'/>
</atom:entry>`
	log.Debug("update signing key")
	// https://developers.google.com/admin-sdk/admin-settings/#managing_single_sign-on_settings
	req, _ = http.NewRequest(http.MethodPut, Url, bytes.NewBufferString(cfg))
	resp, err = client.Do(req)
	if err != nil {
		return fmt.Errorf("update signing key failed: %v", err.Error())
	}
	resp.Body.Close()

	// update key
	return
}
