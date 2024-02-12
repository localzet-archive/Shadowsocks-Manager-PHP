<?php

namespace localzet\ShadowSocks;

class Server
{
    public function __construct(
        protected string $shadowsocks,
        protected string $manager,
        protected string $password,
        protected ?string $run = null,
        protected ?string $plugin = null,
        protected ?string $plugin_opts = null,
    )
    {}
}