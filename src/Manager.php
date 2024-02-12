<?php

namespace localzet\ShadowSocks;

use Exception;

/**
 *
 * Client
 * @method static array|null send(array $data)
 * @method static array|null version()
 * @method static array|null list()
 * @method static array|null flow(?array $options = null) ['startTime' => 0, 'endTime' => time(), 'clear' => true]
 * @method static array|null add(string $port, string $password)
 * @method static array|null pwd(string $port, string $password)
 * @method static array|null del(string $port)
 * @method static array|null ip(string $port)
 */
class Manager
{
    const TYPE_SERVER = 's';
    const TYPE_MANAGER = 'm';

    const COMMAND_VERSION = 'version';
    const COMMAND_LIST = 'list';
    const COMMAND_FLOW = 'flow';
    const COMMAND_ADD = 'add';
    const COMMAND_PWD = 'pwd';
    const COMMAND_DEL = 'del';
    const COMMAND_IP = 'ip';

    const COMMANDS = [
        self::COMMAND_VERSION => [],
        self::COMMAND_LIST => [],
        self::COMMAND_FLOW => ['options'],
        self::COMMAND_ADD => ['port', 'password'],
        self::COMMAND_PWD => ['port', 'password'],
        self::COMMAND_DEL => ['port'],
        self::COMMAND_IP => ['port'],
    ];

    private Server|Client $_instance;

    /**
     * @param string $type 's' | 'm'
     * @param string $manager Server | Client
     * @param string $password Server | Client
     * @param string|null $shadowsocks Server
     * @param string|null $run Server
     * @param string|null $plugin Server
     * @param string|null $plugin_opts Server
     * @throws Exception
     */
    public function __construct(
        protected string  $type,
        protected string $manager,
        protected string $password,
        protected ?string $shadowsocks = null,
        protected ?string $run = null,
        protected ?string $plugin = null,
        protected ?string $plugin_opts = null,
    )
    {
        if ($this->type === self::TYPE_MANAGER) {
            $this->_instance = new Client($this->manager, $this->password);
        } elseif ($this->type === self::TYPE_SERVER) {
            $this->_instance = new Server(
                $this->shadowsocks,
                $this->manager, $this->password,
                $this->run, $this->plugin, $this->plugin_opts
            );
        } else {
            throw new Exception('Неизвестный тип менеджера');
        }

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

        if (str_contains($this->run, 'python')) {
            $type = 'python';
            $tempPassword = 'qwerASDF' . substr((string)mt_rand(), 2, 8);
            $output = shell_exec('ssserver -m ' . $method . ' -p 65535 -k ' . $tempPassword . ' --manager-address ' . $this->shadowsocks);
        } elseif (str_contains($this->run, 'rust')) {
            $type = 'rust';
            $output = shell_exec('ssmanager -m ' . $method . ' -U --manager-address ' . $this->shadowsocks . ' ' . implode(' ', $pluginOptions));
        } else {
            $type = 'libev';
            $output = shell_exec('ss-manager -v -m ' . $method . ' -u --manager-address ' . $this->shadowsocks . ' ' . implode(' ', $pluginOptions));
        }

        echo "Run ShadowSocks (" . $type . ")\n";
        echo "Output: " . $output . "\n";
    }

    public function __call($method, $args)
    {
        if (method_exists($this->_instance, $method)) {
            return call_user_func_array([$this->_instance, $method], $args);
        } else {
            throw new Exception("Метод $method не существует в классе " . get_class($this->_instance));
        }
    }
}