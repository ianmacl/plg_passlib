<?php
/**
 * @copyright	Copyright (C) 2005 - 2012 Open Source Matters, Inc. All rights reserved.
 * @license		GNU General Public License version 2 or later; see LICENSE.txt
 */

// No direct access
defined('_JEXEC') or die;

/**
 * Joomla Authentication plugin
 *
 * @package		Joomla.Plugin
 * @subpackage	Authentication.joomla
 * @since 1.5
 */
class plgAuthenticationPasslib extends JPlugin
{
	/**
	 * This method should handle any authentication and report back to the subject
	 *
	 * @access	public
	 * @param	array	Array holding the user credentials
	 * @param	array	Array of extra options
	 * @param	object	Authentication response object
	 * @return	void
	 * @since 1.5
	 */
	public function onUserAuthenticate($credentials, $options, &$response)
	{
		require_once __DIR__ . '/PasswordLib.phar';

		$response->type = 'Passlib';
		// Joomla does not like blank passwords
		if (empty($credentials['password'])) {
			$response->status = JAuthentication::STATUS_FAILURE;
			$response->error_message = JText::_('JGLOBAL_AUTH_EMPTY_PASS_NOT_ALLOWED');
			return false;
		}

		// Initialise variables.
		$conditions = '';

		// Get a database object
		$db		= JFactory::getDbo();
		$query	= $db->getQuery(true);

		$query->select('u.id, u.password AS password');
		$query->from('#__users AS u');
		$query->join('LEFT', '#__passwords AS p ON u.id = p.user_id');
		$query->where('username=' . $db->Quote($credentials['username']));


		$db->setQuery($query);
		$result = $db->loadObject();

		$verified = false;

		if ($result) {
			$hasher = new \PasswordLib\PasswordLib;

			$test = $hasher->verifyPasswordHash($credentials['password'], $result->password);

			if ($test)
			{
				if (\PasswordLib\Password\Implementation\Joomla::detect($result->password))
				{
					$passwordObject = new stdClass;
					$passwordObject->id = $result->id;

					$passwordObject->password = $hasher->createPasswordHash($credentials['password']);

					$db->updateObject('#__users', $passwordObject, 'id');
				}

				$response->status = JAuthentication::STATUS_SUCCESS;
				$response->error_message = '';

				$user = JUser::getInstance($result->id); // Bring this in line with the rest of the system
				$response->email = $user->email;
				$response->fullname = $user->name;
				if (JFactory::getApplication()->isAdmin())
				{
					$response->language = $user->getParam('admin_language');
				}
				else
				{
					$response->language = $user->getParam('language');
				}
			}
			else
			{
				$response->status = JAuthentication::STATUS_FAILURE;
				$response->error_message = JText::_('JGLOBAL_AUTH_INVALID_PASS');
			}
		}
		else
		{
			// no user object was found for the specified username
			$response->status = JAuthentication::STATUS_FAILURE;
			$response->error_message = JText::_('JGLOBAL_AUTH_NO_USER');
		}
	}
}
