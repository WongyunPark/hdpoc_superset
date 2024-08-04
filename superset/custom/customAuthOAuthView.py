import logging
import re
from typing import Optional

from flask import flash, g, redirect, request, session, url_for
from flask_appbuilder._compat import as_unicode
from flask_appbuilder.baseviews import BaseView
from flask_appbuilder.security.forms import (
    LoginForm_db
)
from flask_appbuilder.security.utils import generate_random_string
from flask_appbuilder.utils.base import get_safe_redirect
from flask_appbuilder.views import expose
from flask_babel import lazy_gettext
from flask_login import login_user, logout_user
import jwt
from werkzeug.wrappers import Response as WerkzeugResponse

import json

log = logging.getLogger(__name__)
# \superset\security\manager.py 의 Auth를 custom으로 설정한다. manager.py에서 명시

class AuthView(BaseView):
    route_base = ""
    login_template = ""
    invalid_login_message = lazy_gettext("Invalid login. Please try again.")
    title = lazy_gettext("Sign In")

    @expose("/login/", methods=["GET", "POST"])
    def login(self):
        pass

    @expose("/logout/")
    def logout(self):
        logout_user()
        return redirect(
            self.appbuilder.app.config.get(
                "LOGOUT_REDIRECT_URL", self.appbuilder.get_url_for_index
            )
        )

class AuthDBView(AuthView):
    login_template = "appbuilder/general/security/login_db.html"

    @expose("/login/", methods=["GET", "POST"])
    def login(self):
        if g.user is not None and g.user.is_authenticated:
            return redirect(self.appbuilder.get_url_for_index)
        form = LoginForm_db()
        if form.validate_on_submit():
            next_url = get_safe_redirect(request.args.get("next", ""))
            user = self.appbuilder.sm.auth_user_db(
                form.username.data, form.password.data
            )
            if not user:
                flash(as_unicode(self.invalid_login_message), "warning")
                return redirect(self.appbuilder.get_url_for_login_with(next_url))
            login_user(user, remember=False)
            return redirect(next_url)
        return self.render_template(
            self.login_template, title=self.title, form=form, appbuilder=self.appbuilder
        )
    
class AuthOAuthView(AuthView):
    login_template = "appbuilder/general/security/login_oauth.html"

    @expose("/login/")
    @expose("/login/<provider>")
    def login(self, provider: Optional[str] = None) -> WerkzeugResponse:
        log.debug("Provider: %s", provider)
        if g.user is not None and g.user.is_authenticated:
            log.debug("Already authenticated %s", g.user)
            return redirect(self.appbuilder.get_url_for_index)

        if provider is None:
            return self.render_template(
                self.login_template,
                providers=self.appbuilder.sm.oauth_providers,
                title=self.title,
                appbuilder=self.appbuilder,
            )

        log.debug("Going to call authorize for: %s", provider)
        random_state = generate_random_string()
        state = jwt.encode(
            request.args.to_dict(flat=False), random_state, algorithm="HS256"
        )
        session["oauth_state"] = random_state
        try:
            if provider == "twitter":
                return self.appbuilder.sm.oauth_remotes[provider].authorize_redirect(
                    redirect_uri=url_for(
                        ".oauth_authorized",
                        provider=provider,
                        _external=True,
                        state=state,
                    )
                )
            else:
                # 수정: refresh 토큰 정보를 가져오기 위해 access_type='offline'설정처리
                return self.appbuilder.sm.oauth_remotes[provider].authorize_redirect(
                    redirect_uri=url_for(
                        ".oauth_authorized", provider=provider, _external=True
                    ),
                    state=state.decode("ascii") if isinstance(state, bytes) else state,access_type='offline', 
                        prompt='consent',      
                        include_granted_scopes='true'    
                )
        except Exception as e:
            log.error("Error on OAuth authorize: %s", e)
            flash(as_unicode(self.invalid_login_message), "warning")
            return redirect(self.appbuilder.get_url_for_index)

    @expose("/oauth-authorized/<provider>")
    def oauth_authorized(self, provider: str) -> WerkzeugResponse:
        log.debug("Authorized init")
        if provider not in self.appbuilder.sm.oauth_remotes:
            flash("Provider not supported.", "warning")
            log.warning("OAuth authorized got an unknown provider %s", provider)
            return redirect(self.appbuilder.get_url_for_login)
        try:
            resp = self.appbuilder.sm.oauth_remotes[provider].authorize_access_token()
        except Exception as e:
            log.error("Error authorizing OAuth access token: %s", e)
            flash("The request to sign in was denied.", "error")
            return redirect(self.appbuilder.get_url_for_login)
        if resp is None:
            flash("You denied the request to sign in.", "warning")
            return redirect(self.appbuilder.get_url_for_login)
        log.debug("OAUTH Authorized resp: %s", resp)
        # Retrieves specific user info from the provider
        try:
            # 추가: bigquery 호출을 위해 session 설정
            self.appbuilder.sm.set_oauth_session(provider, resp)
            userinfo = self.appbuilder.sm.oauth_user_info(provider, resp)
        except Exception as e:
            log.error("Error returning OAuth user info: %s", e)
            user = None
        else:
            log.debug("User info retrieved from %s: %s", provider, userinfo)
            # User email is not whitelisted
            if provider in self.appbuilder.sm.oauth_whitelists:
                whitelist = self.appbuilder.sm.oauth_whitelists[provider]
                allow = False
                for email in whitelist:
                    if "email" in userinfo and re.search(email, userinfo["email"]):
                        allow = True
                        break
                if not allow:
                    flash("You are not authorized.", "warning")
                    return redirect(self.appbuilder.get_url_for_login)
            else:
                log.debug("No whitelist for OAuth provider")
            user = self.appbuilder.sm.auth_user_oauth(userinfo)

        if user is None:
            flash(as_unicode(self.invalid_login_message), "warning")
            return redirect(self.appbuilder.get_url_for_login)
        else:
            try:
                state = jwt.decode(
                    request.args["state"], session["oauth_state"], algorithms=["HS256"]
                )
            except (jwt.InvalidTokenError, KeyError):
                flash(as_unicode("Invalid state signature"), "warning")
                return redirect(self.appbuilder.get_url_for_login)

            login_user(user)

            # oauth_token = dict()
            # oauth_token['token'] = self.appbuilder.sm.oauth_tokengetter()[0]            
            # oauth_token['token_uri'] = 'https://oauth2.googleapis.com/token'
            # oauth_token['client_id'] = ""
            # oauth_token['client_secret'] = ""
            # # oauth_token['refresh_token'] = self.appbuilder.security_manager_class.get_sm_session()['refresh_token']
            # oauth_token['access_token'] = self.appbuilder.security_manager_class.get_sm_session()['access_token']

            # session["user"] = json.dumps(oauth_token)

            next_url = self.appbuilder.get_url_for_index
            # Check if there is a next url on state
            if "next" in state and len(state["next"]) > 0:
                next_url = get_safe_redirect(state["next"][0])
            return redirect(next_url)

