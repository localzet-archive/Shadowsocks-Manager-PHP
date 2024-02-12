<?php

namespace localzet\ShadowSocks;

/**
 * @experimental
 */
class Server extends AbstractSS
{
    use Service\ShadowSocks, Service\Server;

    public function __construct(
        string $address,
        string $password,
        string $run = 'libev',
        ?string $plugin = null,
        ?string $plugin_opts = null
    )
    {
        parent::__construct(
            type: self::TYPE_SERVER,
            shadowsocks: $address,
            password: $password,
            run: $run,
            plugin: $plugin,
            plugin_opts: $plugin_opts,
        );
    }
}