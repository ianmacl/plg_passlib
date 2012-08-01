<?php
/**
 * @copyright	Copyright (C) 2005 - 2009 Open Source Matters, Inc. All rights reserved.
 * @license		GNU General Public License version 2 or later; see LICENSE.txt
 */

// No direct access
defined('_JEXEC') or die;

/**
 * Joomla User plugin
 *
 * @package		Joomla.Plugin
 * @subpackage	User.joomla
 * @since		1.5
 */
class plgUserPasslib extends JPlugin
{
	/**
	 * Utility method to act on a user after it has been saved.
	 *
	 * This method sends a registration email to new users created in the backend.
	 *
	 * @param	array		$user		Holds the new user data.
	 * @param	boolean		$isnew		True if a new user is stored.
	 * @param	boolean		$success	True if user was succesfully stored in the database.
	 * @param	string		$msg		Message.
	 *
	 * @return	void
	 * @since	1.6
	 */
	public function onUserAfterSave($user, $isnew, $success, $msg)
	{
		if (isset($user['password_clear']))
		{
			require_once __DIR__ . '/PasswordLib.phar';

			$hasher = new \PasswordLib\PasswordLib;

			$hash = $hasher->createPasswordHash($user['password_clear']);

			$userObject = new stdClass;

			$userObject->id = $user['id'];
			$userObject->password = $hash;
			
			JFactory::getDbo()->updateObject('#__users', $userObject, 'id');
		}
	}
}
