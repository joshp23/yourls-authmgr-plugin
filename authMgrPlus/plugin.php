<?php
/*
Plugin Name: Auth Manager Plus
Plugin URI:  https://github.com/joshp23/YOURLS-AuthMgrPlus
Description: Role Based Access Controlls with seperated user data for authenticated users
Version:     2.1.1
Author:      Josh Panter, nicwaller, Ian Barber <ian.barber@gmail.com>
Author URI:  https://unfettered.net
*/

// No direct call
if( !defined( 'YOURLS_ABSPATH' ) ) die();

/****************** SET UP CONSTANTS ******************/

class ampRoles { 
	const Administrator = 'Administrator';
	const Editor        = 'Editor';
	const Contributor   = 'Contributor';
}

class ampCap {
	const ShowAdmin     = 'ShowAdmin';
	const AddURL        = 'AddURL';
	const DeleteURL     = 'DeleteURL';
	const EditURL       = 'EditURL';
	const Traceless		= 'Traceless';
	const ManageAnonURL = 'ManageAnonURL';
	const ManageUsrsURL = 'ManageUsrsURL';
	const ManagePlugins = 'ManagePlugins';
	const API           = 'API';
	const APIu          = 'APIu';
	const ViewStats     = 'ViewStats';
	const ViewAll       = 'ViewAll';
}	

/********** Add hooks to intercept functionality in CORE **********/

yourls_add_action( 'load_template_infos', 'amp_intercept_stats' );
function amp_intercept_stats() {
	if ( 'YOURLS_PRIVATE_INFOS' === true ) {
		amp_require_capability( ampCap::ViewStats );
	}
}

yourls_add_action( 'api', 'amp_intercept_api' );
function amp_intercept_api() {
	if ( 'YOURLS_PRIVATE_API' === true ) {
		if ( isset( $_REQUEST['shorturl'] ) || isset( $_REQUEST['stats'] ) ) {
			amp_require_capability( ampCap::APIu );
		} else {
			amp_require_capability( ampCap::API );
		}
	}
}
yourls_add_action( 'auth_successful', function() {
	if( yourls_is_admin() ) amp_intercept_admin();
} );

/**
 * YOURLS processes most actions in the admin page. It would be ideal
 * to add a unique hook for each action, but unfortunately we need to
 * hook the admin page load itself, and try to figure out what action
 * is intended.
 *
 * TODO: look for these hooks
 *
 * At this point, reasonably assume that the current request is for
 * a rendering of the admin page.
 */
function amp_intercept_admin() {
	amp_require_capability( ampCap::ShowAdmin );

	// we use this GET param to send up a feedback notice to user
	if ( isset( $_GET['access'] ) && $_GET['access']=='denied' ) {
		yourls_add_notice('Access Denied');
	}

	$action_capability_map = array(
		'add' => ampCap::AddURL,
		'delete' => ampCap::DeleteURL,
		'edit_display' => ampCap::EditURL,
		'edit_save' => ampCap::EditURL,
		'activate' => ampCap::ManagePlugins,
		'deactivate' => ampCap::ManagePlugins,
	);
	// allow manipulation of this list ( be mindfull of extending Authmp Capability class if needed )
	yourls_apply_filter( 'amp_action_capability_map', $action_capability_map);

	// Key actions like Add/Edit/Delete are AJAX requests
	if ( yourls_is_Ajax() ) {

		// Define some boundaries for ownership
		$restricted_actions = array( 'edit_display',
									'edit_save',
									'delete'
		);

		// Allow some flexability with those boundaries
		yourls_apply_filter( 'amp_restricted_ajax_actions', $restricted_actions );

		$action_keyword = $_REQUEST['action'];
		$cap_needed = $action_capability_map[$action_keyword];

		// Check the action against those boundaries
		if ( in_array( $action_keyword, $restricted_actions) ) {
			$keyword = $_REQUEST['keyword'];
			$do = amp_manage_keyword( $keyword, $cap_needed );
		} else {
			$do = amp_have_capability( $cap_needed );
		}

		if ( $do !== true ) {
			$err = array();
			$err['status'] = 'fail';
			$err['code'] = 'error:authorization';
			$err['message'] = 'Access Denied';
			$err['errorCode'] = '403';
			echo json_encode( $err );
			die();
		}
	}

	// Intercept requests for plugin management
	if( isset( $_SERVER['REQUEST_URI'] ) && preg_match('/\/admin\/plugins\.php.*/', $_SERVER['REQUEST_URI'] ) ) {
		// Is this a plugin page request?
		if ( isset( $_REQUEST['page'] ) ) {
			// Is this an allowed plugin?
			global $amp_allowed_plugin_pages;
			if ( amp_have_capability( ampCap::ManagePlugins ) !== true) {
				$r = $_REQUEST['page'];
				if(!in_array($r, $amp_allowed_plugin_pages ) ) {
					yourls_redirect( yourls_admin_url( '?access=denied' ), 302 );
				}
			}
		} else {
		// Should this user touch plugins?
			if ( amp_have_capability( ampCap::ManagePlugins ) !== true) {
				yourls_redirect( yourls_admin_url( '?access=denied' ), 302 );
			}
		}

		// intercept requests for global plugin management actions
		if (isset( $_REQUEST['plugin'] ) ) {
			$action_keyword = $_REQUEST['action'];
			$cap_needed = $action_capability_map[$action_keyword];
			if ( $cap_needed !== NULL && amp_have_capability( $cap_needed ) !== true) {
				yourls_redirect( yourls_admin_url( '?access=denied' ), 302 );
			}
		}
	}
}

/* 
 * Cosmetic filter: removes disallowed plugins from link list
*/

yourls_add_filter( 'admin_sublinks', 'amp_admin_sublinks' );
function amp_admin_sublinks( $links ) {
	
	global $amp_allowed_plugin_pages;

	if ( amp_have_capability( ampCap::ManagePlugins ) !== true) {
		foreach( $links['plugins'] as $link => $ar ) {
			if(!in_array($link, $amp_allowed_plugin_pages) )
				unset($links['plugins'][$link]);
		}
	}

	if( empty( $links['plugins'] ) )
		yourls_add_filter( 'admin_links', 'amp_admin_links' );
		
	sort($links['plugins']);
	return $links;
}

function amp_admin_links( $links ) {
	unset($links['plugins']);
	return $links;
}
/*
 * Cosmetic filter: displays currently available roles
 * by hovering mouse over the username in logout link.
 */

yourls_add_filter( 'logout_link', 'amp_html_append_roles' );
function amp_html_append_roles( $original ) {
	if ( amp_is_valid_user() ) {
		$listcaps = implode(', ', amp_current_capabilities());
		return '<div title="'.$listcaps.'">'.$original.'</div>';
	} else {
		return $original;
	}
}

/**************** CAPABILITY TESTING ****************/

/*
 * If capability is not permitted in current context, then abort.
 * This is the most basic way to intercept unauthorized usage.
 */
// TODO: API responses!
function amp_require_capability( $capability ) {
	if ( !amp_have_capability( $capability ) ) {
		// If the user can't view admin interface, return a plain error.
		if ( !amp_have_capability( ampCap::ShowAdmin ) ) {
		//	header("HTTP/1.0 403 Forbidden");
			die('Require permissions to show admin interface.');
		}
		// Otherwise, render errors in admin interface
		yourls_redirect( yourls_admin_url( '?access=denied' ), 302 );
		die();
	}
}

// Heart of system - Can the user do "X"?
function amp_have_capability( $capability ) {

	global $amp_anon_capabilities;
	global $amp_role_capabilities;
	global $amp_admin_ipranges;

	// Make sure the environment has been setup
	amp_env_check();

	// Check anon capabilities
	$return = in_array( $capability, $amp_anon_capabilities );

	// Check user-role based auth
	if( !$return ) {
		// Only users have roles
		if ( !amp_is_valid_user() ) //XXX
			return false;
		// List capabilities of particular user role
		$user = YOURLS_USER !== false ? YOURLS_USER : NULL;
		$user_caps = array();
		foreach ( $amp_role_capabilities as $rolename => $rolecaps ) {
				if ( amp_user_has_role( $user, $rolename ) ) {
						$user_caps = array_merge( $user_caps, $rolecaps );
				}
		}
		$user_caps = array_unique( $user_caps );
		// Is the requested capability in this list?
		$return =  in_array( $capability, $user_caps );
	}

	// Is user connecting from an admin designated IP?
	if( !$return ) {
		// the array of ranges: '127.0.0.0/8' will always be admin
		foreach ($amp_admin_ipranges as $range) {
			$return = amp_cidr_match( $_SERVER['REMOTE_ADDR'], $range );
			if( $return ) 
				break;
		}
	}
	return $return;
}

// Determine whether a specific user has a role.
function amp_user_has_role( $username, $rolename ) {

	global $amp_role_assignment;

	// if no role assignments are created, grant everything FIXME: Make 'admin'
	// so the site still works even if stuff is configured wrong
	if ( empty( $amp_role_assignment ) )
		return true;

	// do this the case-insensitive way
	// the entire array was made lowercase in environment check
	$username = strtolower($username);
	$rolename = strtolower($rolename);

	// if the role doesn't exist, give up now.
	if ( !in_array( $rolename, array_keys( $amp_role_assignment ) ) )
		return false;

	$users_in_role = $amp_role_assignment[$rolename];
	return in_array( $username, $users_in_role );	
}

/********************* KEYWORD OWNERSHIP ************************/

// Filter out restricted access to keyword data in...
// Admin list
yourls_add_filter( 'admin_list_where', 'amp_admin_list_where' );
function amp_admin_list_where($where) {

	if ( amp_have_capability( ampCap::ViewAll ) )
		return $where; // Allow admin/editor users to see the lot. 

	$user = YOURLS_USER !== false ? YOURLS_USER : NULL;
	$where['sql'] = $where['sql'] . " AND (`user` = :user OR `user` IS NULL) ";
	$where['binds']['user'] = $user;

	return $where;
}

// API stats
yourls_add_filter( 'api_url_stats', 'amp_api_url_stats' );
function amp_api_url_stats( $return, $shorturl ) {

	$keyword = str_replace( YOURLS_SITE . '/' , '', $shorturl ); // accept either 'http://ozh.in/abc' or 'abc'
	$keyword = yourls_sanitize_string( $keyword );
	$keyword = addslashes($keyword);

	if( ( !defined('YOURLS_PRIVATE_INFOS') || YOURLS_PRIVATE_INFOS !== false ) 
			&& !amp_access_keyword($keyword) )
		return array('simple' => "URL is owned by another user", 'message' => 'URL is owned by another user', 'errorCode' => 403);

	else
		return $return;
}

// Info pages
yourls_add_action( 'pre_yourls_infos', 'amp_pre_yourls_infos' );
function amp_pre_yourls_infos( $keyword ) {

	if( yourls_is_private() && !amp_access_keyword($keyword) ) {

		if ( !amp_is_valid_user() ) 
			yourls_redirect( yourls_admin_url( '?access=denied' ), 302 );
		else
			yourls_redirect( YOURLS_SITE, 302 );
	}
}

// DB stats
yourls_add_filter( 'get_db_stats', 'amp_get_db_stats' );
function amp_get_db_stats( $return, $where ) {

	if ( amp_have_capability( ampCap::ViewAll ) )
		return $return; // Allow admin/editor users to see the lot. 

	// or... filter results
	global $ydb;
	$table_url = YOURLS_DB_TABLE_URL;
	$user = YOURLS_USER !== false ? YOURLS_USER : NULL;

	$where['sql'] = $where['sql'] . " AND (`user` = :user OR `user` IS NULL) ";
	$where['binds']['user'] = $user;

	$sql = "SELECT COUNT(keyword) as count, SUM(clicks) as sum FROM `$table_url` WHERE 1=1 " . $where['sql'];
	$binds = $where['binds'];

	$totals = $ydb->fetchObject($sql, $binds);

	$return = array( 'total_links' => $totals->count, 'total_clicks' => $totals->sum );

	return $return;
}

// Fine tune track-me-not
yourls_add_action('redirect_shorturl', 'amp_tracking');
function amp_tracking( $u, $k = false ) {
	if( amp_is_valid_user() && ( amp_keyword_owner($k) || amp_have_capability( ampCap::Traceless ) ) ) {
		// No logging
		yourls_add_filter( 'shunt_update_clicks', 	function(  ) { return true; } );
		yourls_add_filter( 'shunt_log_redirect', 	function(  ) { return true; } );
	}
}
/********************* HOUSEKEEPING ************************/
// Validate environment setup
function amp_env_check() {
	global $amp_anon_capabilities;
	global $amp_role_capabilities;
	global $amp_role_assignment;
	global $amp_admin_ipranges;
	global $amp_allowed_plugin_pages;

	if ( !isset( $amp_anon_capabilities) ) {
		$amp_anon_capabilities = array();
	}

	if ( !isset( $amp_role_capabilities) ) {
		$amp_role_capabilities = array(
			ampRoles::Administrator => array(
				ampCap::ShowAdmin,
				ampCap::AddURL,
				ampCap::EditURL,
				ampCap::DeleteURL,
				ampCap::Traceless,
				ampCap::ManageAnonURL,
				ampCap::ManageUsrsURL,
				ampCap::ManagePlugins,
				ampCap::API,
				ampCap::APIu,
				ampCap::ViewStats,
				ampCap::ViewAll,
			),
			ampRoles::Editor => array(
				ampCap::ShowAdmin,
				ampCap::AddURL,
				ampCap::EditURL,
				ampCap::DeleteURL,
				ampCap::Traceless,
				ampCap::ManageAnonURL,
				ampCap::APIu,
				ampCap::ViewStats,
				ampCap::ViewAll,
			),
			ampRoles::Contributor => array(
				ampCap::ShowAdmin,
				ampCap::AddURL,
				ampCap::EditURL,
				ampCap::DeleteURL,
				ampCap::APIu,
				ampCap::ViewStats,
			),
		);
	}

	if ( !isset( $amp_role_assignment ) ) {
		$amp_role_assignment = array();
	}

	if ( !isset( $amp_admin_ipranges ) ) {
		$amp_admin_ipranges = array(
			'127.0.0.0/8',
		);
	}

	if ( !isset( $amp_allowed_plugin_pages ) ) {
		$amp_allowed_plugin_pages = array(
		);
	}

	// convert role assignment table to lower case if it hasn't been done already
	// this makes searches much easier!
	$amp_role_assignment_lower = array();
	foreach ( $amp_role_assignment as $key => $value ) {
		$t_key = strtolower( $key );
		$t_value = array_map('strtolower', $value);
		$amp_role_assignment_lower[$t_key] = $t_value;
	}
	$amp_role_assignment = $amp_role_assignment_lower;
	unset($amp_role_assignment_lower);

	// allow manipulation of env by other plugins 
	// be mindfull of extending ampCap and ampRoles classes if needed
	$a = $amp_anon_capabilities;
	$b = $amp_role_capabilities;
	$c = $amp_role_assignment;
	$d = $amp_admin_ipranges;
	$e = $amp_allowed_plugin_pages;

	yourls_apply_filter( 'amp_env_check', $a, $b, $c, $d, $e );

	return true;
}

// Activation: add the user column to the URL table if not added
yourls_add_action( 'activated_authMgrPlus/plugin.php', 'amp_activated' );
function amp_activated() {
	global $ydb; 
    
	$table = YOURLS_DB_TABLE_URL;
	$sql = "DESCRIBE `$table`";
	$results = $ydb->fetchObjects($sql);

	$activated = false;
	foreach($results as $r) {
		if($r->Field == 'user') {
			$activated = true;
		}
	}
	if(!$activated) {
		if ($version) {
			$sql = "ALTER TABLE `$table` ADD `user` VARCHAR(255) NULL";
			$insert = $ydb->fetchAffected($sql);
		} else {
			$ydb->query("ALTER TABLE `$table` ADD `user` VARCHAR(255) NULL");

		}
	}
}

/***************** HELPER FUNCTIONS ********************/

// List currently available capabilities
function amp_current_capabilities() {
	$current_capabilities = array();
	$all_capabilities = array(
		ampCap::ShowAdmin,
		ampCap::AddURL,
		ampCap::EditURL,
		ampCap::DeleteURL,
		ampCap::Traceless,
		ampCap::ManageAnonURL,
		ampCap::ManageUsrsURL,
		ampCap::ManagePlugins,
		ampCap::API,
		ampCap::APIu,
		ampCap::ViewStats,
		ampCap::ViewAll,
	);
	// allow manipulation of this list ( be mindfull of extending the ampCap class if needed )
	yourls_apply_filter( 'amp_current_capabilities', $all_capabilities);

	foreach ( $all_capabilities as $cap ) {
		if ( amp_have_capability( $cap ) ) {
			$current_capabilities[] = $cap;
		}
	}

	return $current_capabilities;
}

// Check for IP in a range
// from: http://stackoverflow.com/questions/594112/matching-an-ip-to-a-cidr-mask-in-php5
function amp_cidr_match($ip, $range) {
	list ($subnet, $bits) = explode('/', $range);
	$ip = ip2long($ip);
	$subnet = ip2long($subnet);
	$mask = -1 << (32 - $bits);
	$subnet &= $mask; # nb: in case the supplied subnet wasn't correctly aligned
	return ($ip & $mask) == $subnet;
}

// Check user access to a keyword ( can they see it )
function amp_access_keyword( $keyword ) {

	$users = array( YOURLS_USER !== false ? YOURLS_USER : NULL , NULL );
	$owner = amp_keyword_owner( $keyword );
	if ( amp_have_capability( ampCap::ViewAll ) || in_array( $owner , $users ) )
		return true;
}

// Check user rights to a keyword ( can manage it )
function amp_manage_keyword( $keyword, $capability ) {
	// only authenticated users can manaage keywords
	if ( !amp_is_valid_user() )
		return false;
	// Admin?
	if ( amp_have_capability( ampCap::ManageUsrsURL ) )
		return true;
	// Editor?
	$owner = amp_keyword_owner($keyword);
	if ( $owner === null && amp_have_capability( ampCap::ManageAnonURL ) )
		return true;
	
	// Self Edit?
	$user = YOURLS_USER !== false ? YOURLS_USER : NULL;
	if ( $owner === $user && amp_have_capability( $capability ) )
			return true;
		else
			return false;
	return false;
}

// Check keyword ownership
function amp_keyword_owner( $keyword ) {
	global $ydb; 
	$table = YOURLS_DB_TABLE_URL;
	$binds = array( 'keyword' => $keyword );
	$sql = "SELECT * FROM `$table` WHERE `keyword` = :keyword";
	$result = $ydb->fetchOne($sql, $binds);
	return $result['user'];
}

// Record user info on keyword creation
yourls_add_action( 'insert_link', 'amp_insert_link' );
function amp_insert_link($actions) {
	global $ydb; 

	$keyword = $actions[2];
	$user = YOURLS_USER !== false ? YOURLS_USER : NULL;
	$table = YOURLS_DB_TABLE_URL;

	// Insert $keyword against $username
	$binds = array( 'user' => $user,
					'keyword' => $keyword);
	$sql = "UPDATE `$table` SET  `user` = :user WHERE `keyword` = :keyword";
	$result = $ydb->fetchAffected($sql, $binds);
}

// Quick user validation without triggering hooks
function amp_is_valid_user() {

	$valid = defined( 'YOURLS_USER' ) ? true : false;

	if ( !$valid ) {

		if ( yourls_is_API() 
			&& isset( $_REQUEST['timestamp'] ) && !empty($_REQUEST['timestamp'] ) 
			&& isset( $_REQUEST['signature'] ) && !empty($_REQUEST['signature'] ) )
			$valid = yourls_check_signature_timestamp();
		elseif ( yourls_is_API() 
			&& !isset( $_REQUEST['timestamp'] ) 
			&& isset( $_REQUEST['signature'] ) && !empty( $_REQUEST['signature'] ) )
			$valid = yourls_check_signature();
		elseif ( isset( $_REQUEST['username'] ) && isset( $_REQUEST['password'] )
			&&  !empty( $_REQUEST['username'] ) && !empty( $_REQUEST['password']  ) )
			$valid = yourls_check_username_password();
		elseif ( !yourls_is_API() && isset( $_COOKIE[ yourls_cookie_name() ] ) )
			$valid = yourls_check_auth_cookie();
	}

	return $valid;
}
?>
