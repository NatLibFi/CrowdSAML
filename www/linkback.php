<?php

/**
 * Handle callback from Crowd.
 */

if (!array_key_exists('AuthState', $_REQUEST) || empty($_REQUEST['AuthState'])) {
	throw new SimpleSAML_Error_BadRequest('Missing state parameter on Crowd linkback endpoint.');
}
$state = SimpleSAML_Auth_State::loadState($_REQUEST['AuthState'], sspmod_authcrowd_Auth_Source_Crowd::STAGE_INIT);

// Find authentication source
if (!array_key_exists(sspmod_authcrowd_Auth_Source_Crowd::AUTHID, $state)) {
	throw new SimpleSAML_Error_BadRequest('No data in state for ' . sspmod_authcrowd_Auth_Source_Crowd::AUTHID);
}
$sourceId = $state[sspmod_authcrowd_Auth_Source_Crowd::AUTHID];

$source = SimpleSAML_Auth_Source::getById($sourceId);
if ($source === NULL) {
	throw new SimpleSAML_Error_BadRequest('Could not find authentication source with id ' . var_export($sourceId, TRUE));
}

try {
	$source->finalStep($state);
} catch (SimpleSAML_Error_Exception $e) {
	SimpleSAML_Auth_State::throwException($state, $e);
} catch (Exception $e) {
	SimpleSAML_Auth_State::throwException($state, new SimpleSAML_Error_AuthSource($sourceId, 'Error on authcrowd linkback endpoint.', $e));
}

SimpleSAML_Auth_Source::completeAuth($state);
