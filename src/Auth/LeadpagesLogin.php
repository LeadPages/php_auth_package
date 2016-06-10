<?php

namespace Leadpages\Auth;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\ClientException;
use Leadpages\Auth\Contracts\LeadpagesToken;

abstract class LeadpagesLogin implements LeadpagesToken
{

    protected $client;
    public $response;

    /**
     * Token label that should be used to reference the token in the database for consistency across platforms
     * and upgrades easier
     * @var string
     */
    public $tokenLabel = 'leadpages_security_token';

    public $token;

    public function __construct(Client $client)
    {

        $this->client        = $client;
        $this->loginurl      = 'https://api.leadpages.io/auth/v1/sessions/';
        $this->loginCheckUrl = 'https://api.leadpages.io/auth/v1/sessions/current';
    }

    protected function hashUserNameAndPassword($username, $password)
    {
        return base64_encode($username . ':' . $password);
    }

    /**
     * get user information
     *
     * @param $username
     * @param $password
     *
     * @return array|\GuzzleHttp\Message\FutureResponse|\GuzzleHttp\Message\ResponseInterface|\GuzzleHttp\Ring\Future\FutureInterface|null
     */

    public function getUser($username, $password)
    {
        $authHash = $this->hashUserNameAndPassword($username, $password);

        try {
            $response       = $this->client->post(
              $this->loginurl, //url
              [
                'headers' => ['Authorization' => 'Basic ' . $authHash],
                'body'    => ['clientType' => 'wp-plugin'] //wp-plugin value makes session not expire
              ]);
            $this->response = $response->getBody();
            return $this;

        } catch (ClientException $e) {
            $response       = [
              'code'     => $e->getCode(),
              'response' => $e->getMessage(),
              'error'    => (bool)true
            ];
            $this->response = json_encode($response);
            return $this;
        }
    }

    /**
     * Check to see if you get a proper response back if you use the token stored in your DB
     * @return bool
     */
    public function checkCurrentUserToken()
    {
        try {
            $response       = $this->client->get(
              $this->loginCheckUrl,
              [
                'headers' => ['LP-Security-Token' => $this->token]
              ]);
            //return true as token is good
            $responseArray = json_decode($response->getBody(), true);
            if(isset($responseArray['securityToken'])) {
                return true;
            }else{
                return false;
            }
        } catch (ClientException $e) {
            //return false as token is bad
            return false;
        }
    }

    /**
     * Parse response for call to Leadpages Login. If response does
     * not contain a error we will return a response with
     * HttpResponseCode and Message
     *
     * @param bool $deleteTokenOnFail
     *
     * @return mixed
     */
    public function parseResponse($deleteTokenOnFail = false)
    {
        $responseArray = json_decode($this->response, true);
        if (isset($responseArray['error']) && $responseArray['error'] == true) {
            //token should be unset assumed to be no longer valid
            unset($this->token);
            //delete token from data store if param is passed
            if($deleteTokenOnFail == true){
                $this->deleteToken();
            }
            return $this->response; //return json encoded response for client to handle
        }
        $this->token = $responseArray['securityToken'];
        return 'success';
    }

    public function getLeadpagesResponse()
    {
        return $this->response;
    }

    /**
     * set response property. really did not want to make this method
     * but it is needed for testing
     *
     * @param $response
     */
    public function setLeadpagesResponse($response)
    {
        $this->response = $response;
    }


}