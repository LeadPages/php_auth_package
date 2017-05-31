<?php

namespace Leadpages\Auth;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Exception\ConnectException;
use Leadpages\Auth\Contracts\LeadpagesToken;

abstract class LeadpagesLogin implements LeadpagesToken
{

    protected $client;
    public $response;
    public $keyUrl = 'https://api.leadpages.io/account/v1/keys';
    public $loginurl = 'https://api.leadpages.io/account/v1/sessions';

    /**
     * Token label that should be used to reference the token in the database for consistency across platforms
     * and upgrades easier
     * @var string
     */
    public $tokenLabel = 'leadpages_security_token';

    public $apiKeyLabel = 'leadpages_api_key';

    public $token;

    public $apiKey;

    public $certFile;

    public function __construct(Client $client)
    {
        $this->client = $client;
        $this->certFile = ABSPATH . WPINC . '/certificates/ca-bundle.crt';
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
        $body     = json_encode(['clientType' => 'wp-plugin']);
        try {
            $response = $this->client->post(
              $this->loginurl, [
                'headers' => ['Authorization' => 'Basic ' . $authHash],
                'verify'  => $this->certFile,
                'body'    => $body //wp-plugin value makes session not expire
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

        } catch (ConnectException $e) {
            $message = 'Can not connect to Leadpages Server:';
            $response = $this->parseException($e, $message);
            $this->response = $response;
            return $this;
        }
    }

	/**
	 * Create an API key for account
	 *
	 * @return string|boolean JSON encode key or false
	 */	
	public function createApiKey()
	{
        $authHeader = 'LP-Security-Token';
        if (stripos($this->token, 'lp ') === 0) {
            $authHeader = 'Authorization';
        }

        try {
            $response = $this->client->post($this->keyUrl, [
                'headers' => [
                    $authHeader => $this->token,
                    'Content-Type' => 'application/json',
                ],
				'verify' => $this->certFile,
				'body' => json_encode(['label' => 'wordpress-plugin']),
            ]);
            
			$body = json_decode($response->getBody(), true);

			if (array_key_exists('value', $body)) {
                $response = $body['value'];
            } else {
				$response = false;
			}

        } catch (ClientException $e) {
            //return false as token is bad
            $response = false;

        } catch (ConnectException $e) {
            $response = false;
        }

        return $response;
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
            if ($deleteTokenOnFail == true) {
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

    /**
     * @param $e
     *
     * @param string $message
     *
     * @return array
     */
    public function parseException($e, $message = '')
    {
        $response = [
          'code'     => $e->getCode(),
          'response' => $message . ' ' . $e->getMessage(),
          'error'    => (bool)true
        ];
        return $response;
    }


}
