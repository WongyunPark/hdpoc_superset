import logging
from superset.security import SupersetSecurityManager
from flask import session
from werkzeug.security import check_password_hash, generate_password_hash
log = logging.getLogger(__name__)

class CustomSsoSecurityManager(SupersetSecurityManager):
    # flask_appbuilder\security\manager.py 의 oauth를 custom으로 설정한다.  
    # config 파일에서 명시 CUSTOM_SECURITY_MANAGER = CustomSsoSecurityManager

    def oauth_user_info(self, provider, response=None):
        # 추가 : 필요한 정보에 맞게 userInfo 수정 적용
        logging.info("Oauth2 provider: {0}.".format(provider))
        if provider == 'google':
            me = self.appbuilder.sm.oauth_remotes[provider].get('userinfo')  
            data = me.json()  
            user = {
                "username": data.get("email", ""),
                "first_name": data.get("given_name", ""),
                "last_name": data.get("family_name", ""),
                "email": data.get("email", ""),
                "name": data.get("name", "")
            }
            return user

    def auth_user_oauth(self, userinfo):
        """
        Method for authenticating user with OAuth.

        :userinfo: dict with user information
                   (keys are the same as User model columns)
        """
        # extract the username from `userinfo`
        if "username" in userinfo:
            username = userinfo["username"]
        elif "email" in userinfo:
            username = userinfo["email"]
        else:
            log.error("OAUTH userinfo does not have username or email %s", userinfo)
            return None

        # If username is empty, go away
        if (username is None) or username == "":
            return None

        # Search the DB for this user
        user = self.find_user(username=username)

        # If user is not active, go away
        if user and (not user.is_active):
            return None

        # If user is not registered, and not self-registration, go away
        if (not user) and (not self.auth_user_registration):
            return None

        # Sync the user's roles
        if user and self.auth_roles_sync_at_login:
            user.roles = self._oauth_calculate_user_roles(userinfo)
            log.debug("Calculated new roles for user='%s' as: %s", username, user.roles)

        # If the user is new, register them
        if (not user) and self.auth_user_registration:
            user = _add_user(
                self,
                username=username,
                first_name=userinfo.get("first_name", ""),
                last_name=userinfo.get("last_name", ""),
                email=userinfo.get("email", "") or f"{username}@email.notfound",
                role=self._oauth_calculate_user_roles(userinfo),
            )
            log.debug("New user registered: %s", user)

            # If user registration failed, go away
            if not user:
                log.error("Error creating a new OAuth user %s", username)
                return None

        # LOGIN SUCCESS (only if user is now registered)
        if user:
            self.update_user_auth_stat(user)
            return user
        else:
            return None
        
    # 추가: bigquery 인증시 사용하기 위해 추가처리    
    def set_oauth_session(self, provider, oauth_response):
        """
            Set the current session with OAuth user secrets
        """
        super().set_oauth_session(provider, oauth_response)
        logging.info(oauth_response["access_token"] )
        session["access_token"] = oauth_response["access_token"]            
        session["id_token"] = oauth_response["id_token"]       
        session["refresh_token"] = oauth_response["refresh_token"]

    # 추가: bigquery 인증시 사용하기 위해 추가처리
    def get_sm_session():
        return session
        
def _add_user(
        self,
        username,
        first_name,
        last_name,
        email,
        role,
        password="",
        hashed_password="",
):
    """
    Generic function to create user
    """
    try:
        user = self.user_model()
        user.first_name = first_name
        user.last_name = last_name
        user.username = username
        user.email = email
        user.active = True
        user.roles = role if isinstance(role, list) else [role]
        if hashed_password:
            user.password = hashed_password
        else:
            user.password = generate_password_hash(password)
        self.get_session.add(user)
        self.get_session.commit()
        # log.info(c.LOGMSG_INF_SEC_ADD_USER, username)
        return user
    except Exception as e:
        # log.error(c.LOGMSG_ERR_SEC_ADD_USER, e)
        self.get_session.rollback()
        return False
        
    
