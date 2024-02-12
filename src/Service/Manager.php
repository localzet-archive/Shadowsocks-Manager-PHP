<?php

namespace localzet\ShadowSocks\Service;

use Exception;

trait Manager
{
    private function pack($data, $password): string
    {
        $message = json_encode($data);
        $now = time();
        $timeBuffer = dechex($now);
        $dataBuffer = $message;
        $length = strlen($dataBuffer) + 4 + 6;
        $lengthBuffer = dechex($length);
        $code = substr(md5($now . $message . $password), 0, 8);
        return $lengthBuffer . $timeBuffer . $dataBuffer . $code;
    }

    private function checkData($buffer)
    {
        if (strlen($buffer) < 4) {
            return null;
        }
        $length = hexdec(substr($buffer, 0, 4));
        if (strlen($buffer) >= $length + 4) {
            $data = substr($buffer, 4, $length + 4);
            return json_decode($data, true);
        } else {
            return null;
        }
    }

    /**
     * @param $data
     * @param $options ['host', 'port', 'password']
     * @return mixed|null
     * @throws Exception
     */
    private function sendMessage($data, ?array $options = null): mixed
    {
        $host = $options['host'] ?? $this->host;
        $port = $options['port'] ?? $this->port;
        $password = $options['password'] ?? $this->password;

        if ($host) {
            if (str_contains($host, ':')) {
                [$host, $port] = explode(':', $host, 2);
            }
        }

        $client = fsockopen($host, $port);
        if (!$client) {
            throw new Exception("Could not open socket");
        }
        fwrite($client, $this->pack($data, $password));
        stream_set_timeout($client, 10);
        $receive = '';
        while (!feof($client)) {
            $receive .= fgets($client, 128);
        }
        fclose($client);
        $message = $this->checkData($receive);
        if (isset($message['code']) && $message['code'] === 0) {
            return $message['data'];
        } else {
            echo "Произошла ошибка: " . json_encode($message);
            return false;
        }
    }

    private function getIps($address)
    {
        if (filter_var($address, FILTER_VALIDATE_IP)) {
            return [$address];
        }
        return gethostbynamel($address);
    }

    public function send($data, $options)
    {
        $host = $options['host'] ?? $this->host;
        $port = $options['port'] ?? $this->port;
        $password = $options['password'] ?? $this->password;

        if ($host) {
            if (str_contains($host, ':')) {
                [$host, $port] = explode(':', $host, 2);
            }
        }

        $ips = $this->getIps($host);
        if (count($ips) === 0) {
            throw new Exception("$host invalid ip");
//        } elseif (count($ips) === 1) {
//            return $this->sendMessage($data, $options);
        } else {
            $results = [];
            foreach ($ips as $ip) {
                try {
                    $results[$ip] = $this->sendMessage($data, ['host' => $ip, 'port' => $port, 'password' => $password]);
                } catch (Exception $e) {
                    $results[$ip] = null;
                }
            }

            if ($data['command'] === 'version') {
                $successMark = true;
                $versions = [];
                $ret = ['isGfw' => false];
                foreach ($results as $result_ip => $result) {
                    if ($result) {
                        $versions[] = $result['version'];
                        if ($result['isGfw']) {
                            $ret['isGfw'] = true;
                        }
                    } else {
                        $successMark = false;
                    }
                }
                if (count($versions) === 1) {
                    $ret['version'] = $versions[0] ?? '';
                } else {
                    $diff = count(array_unique($versions)) > 1;
                    if ($diff) {
                        $ret['version'] = implode(',', $versions) ?? '';
                    } else {
                        $ret['version'] = $versions[0] . ' x ' . count($versions);
                    }
                }
                $ret['number'] = count($versions);
                return $successMark ? $ret : null;
            } elseif ($data['command'] === 'flow') {
                $successMark = false;
                $flows = [];
                foreach ($results as $result_ip => $result) {
                    if ($result) {
                        $successMark = true;
                        foreach ($result as $f) {
                            if (!isset($flows[$f['port']])) {
                                $flows[$f['port']] = $f['sumFlow'];
                            } else {
                                $flows[$f['port']] += $f['sumFlow'];
                            }
                        }
                    }
                }
                $ret = [];
                foreach ($flows as $port => $sumFlow) {
                    $ret[] = ['port' => $port, 'sumFlow' => $sumFlow];
                }
                return $successMark ? $ret : null;
            } elseif ($data['command'] === 'list') {
                $successMark = false;
                $ports = [];
                foreach ($results as $result_ip => $result) {
                    if ($result) {
                        $successMark = true;
                        foreach ($result as $f) {
                            if (!isset($ports[$f['port']])) {
                                $ports[$f['port']] = ['password' => $f['password'], 'number' => 1];
                            } else {
                                $ports[$f['port']]['number'] += 1;
                            }
                        }
                    }
                }
                $ret = [];
                foreach ($ports as $port => $info) {
                    if ($info['number'] >= count(array_filter($results))) {
                        $ret[] = ['port' => $port, 'password' => $info['password']];
                    }
                }
                return $successMark ? $ret : null;
            } else {
                return $results;
            }
        }
    }
}