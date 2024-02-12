<?php

namespace localzet\ShadowSocks;

use stdClass;

class Manager extends AbstractSS
{
    use Service\Manager;

    private ?string $host = '127.0.0.1';
    private ?string $port = '6001';

    public function __construct(string $address, string $secret)
    {
        parent::__construct(
            type: self::TYPE_MANAGER,
            manager: $address,
            password: $secret,
        );

        if (str_contains($address, ':')) {
            [$this->host, $this->port] = explode(':', $address);
        }
    }

    public function send(stdClass $data, ?stdClass $options = null)
    {
        if ($options && $options?->host) {
            $options->host = explode(':', $options->host)[0];
        }

        if ($options) {
            $options = (object)['host' => $this->host, 'port' => $this->port, 'password' => $this->password];
        }
    }
}