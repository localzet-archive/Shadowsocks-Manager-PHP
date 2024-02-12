<?php

namespace localzet\ShadowSocks;

abstract class AbstractSS
{
    /**
     * @const string TYPE_SERVER
     */
    const TYPE_SERVER = 's';

    /**
     * @default
     * @const string TYPE_MANAGER
     */
    const TYPE_MANAGER = 'm';

    /**
     * @param string $type
     * @param string|null $shadowsocks
     * @param string|null $manager
     * @param string|null $password
     * @param string|null $run
     * @param string|null $plugin
     * @param string|null $plugin_opts
     */
    public function __construct(
        protected string  $type,
        protected ?string $shadowsocks = null,
        protected ?string $manager = null,
        protected ?string $password = null,
        protected ?string $run = null,
        protected ?string $plugin = null,
        protected ?string $plugin_opts = null,
    )
    {
        if (!$this->run) return;
        if (is_bool($this->run)) $this->run = '';

        $method = 'chacha20-ietf-poly1305';
        $method = str_contains($this->run, ':') ? explode(':', $this->run)[1] ?? $method : $method;

        $pluginOptions = [];
        if ($this->plugin) {
            $pluginOptions[] = '--plugin';
            $pluginOptions[] = $this->plugin;
        }
        if ($this->plugin_opts) {
            $pluginOptions[] = '--plugin-opts';
            $pluginOptions[] = $this->plugin_opts;
        }

        $command = '';
        if (str_contains($this->run, 'python')) {
            $type = 'python';
            $tempPassword = 'qwerASDF' . substr((string)mt_rand(), 2, 8);
            $command = 'ssserver -m ' . $method . ' -p 65535 -k ' . $tempPassword . ' --manager-address ' . $this->shadowsocks;
        } elseif (str_contains($this->run, 'rust')) {
            $type = 'rust';
            $command = 'ssmanager -m ' . $method . ' -U --manager-address ' . $this->shadowsocks . ' ' . implode(' ', $pluginOptions);
        } else {
            $type = 'libev';
            $command = 'ss-manager -v -m ' . $method . ' -u --manager-address ' . $this->shadowsocks . ' ' . implode(' ', $pluginOptions);
        }

        $output = shell_exec($command);

        echo "Run ShadowSocks (" . $this->type . ")\n";
        echo "Output: " . $output . "\n";
    }
}