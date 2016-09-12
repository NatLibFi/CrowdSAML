<?php

require_once(dirname(dirname(dirname(dirname(__FILE__)))) . '/auth.php');

/**
 * Authenticate using Crowd.
 *
 * @package SimpleSAMLphp
 */
class sspmod_authCrowd_Auth_Source_Crowd extends SimpleSAML_Auth_Source {

	/**
	 * The string used to identify our states.
	 */
	const STAGE_INIT = 'crowd:init';

	/**
	 * The key of the AuthId field in the state.
	 */
	const AUTHID = 'crowd:AuthId';

	private $url;
        private $loginUrl;
	private $username;
	private $password;
        private $crowd;

	/**
	 * Constructor for this authentication source.
	 *
	 * @param array $info  Information about this authentication source.
	 * @param array $config  Configuration.
	 */
	public function __construct($info, $config) {
		assert('is_array($info)');
		assert('is_array($config)');

		// Call the parent constructor first, as required by the interface
		parent::__construct($info, $config);

		$configObject = SimpleSAML_Configuration::loadFromArray($config, 'authsources[' . var_export($this->authId, TRUE) . ']');

		$this->url = $configObject->getString('url');
		$this->loginUrl = $configObject->getString('loginUrl');
		$this->username = $configObject->getString('username');
		$this->password = $configObject->getBoolean('password');

                $this->crowd = new CrowdApi($this->url, $this->username, $this->password);
	}


	/**
	 * Log-in using Crowd
	 *
	 * @param array &$state  Information about the current authentication.
	 */
	public function authenticate(&$state) {
		assert('is_array($state)');

		// We are going to need the authId in order to retrieve this authentication source later
		$state[self::AUTHID] = $this->authId;
		
		$stateID = SimpleSAML_Auth_State::saveState($state, self::STAGE_INIT);
	
                $username = $this->crowd->authenticateCookie();

                if ($username !== null) {
                    // we already have the information of the logged in user;
                    // do whatever we need to do afterwards
                    $this->finalStep($state, $username);
                    return;
                }

                // we are not logged in yet, let's direct the user to log in

                $returnUrl = sprintf(
                    '%s?%s',
                    $this->loginUrl,
                    http_build_query(['ssoPayload' => base64_encode($sso->getPayload())], '', '&', PHP_QUERY_RFC3986)
                );

                SimpleSAML\Logger::debug('Redirecting to authentication portal');
		$linkback = SimpleSAML\Module::getModuleURL('authcrowd/linkback.php', array('AuthState' => $stateID));
                $query = http_build_query(['redirectTo' => $linkback], '', '&', PHP_QUERY_RFC3986);
                header(sprintf('Location: %s?%s', $this->crowdUrl, $query), true, 302);

                return false;
	}
	
	
	public function finalStep(&$state, $username = null) {
                if(!$username) {
                        $username = $this->crowd->authenticateCookie();
                }

		if (!$username) {
			throw new SimpleSAML_Error_AuthSource($this->authId, 'Authentication error: no username.');
		}
                
                $userdata = $this->crowd->getUser($username);

                if (!$userdata['email']) {
			throw new SimpleSAML_Error_AuthSource($this->authId, 'Authentication error: no email address found for user.');
		}
                
		$attributes = array();
		
		$attributes['User.Username'] = array($username);
		$attributes['User.Email'] = array($userdata['email']);
		$attributes['User.FirstName'] = array($userdata['first-name']);
		$attributes['User.LastName'] = array($userdata['last-name']);
			
		$state['Attributes'] = $attributes;
	}

}
