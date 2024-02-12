<?php

namespace localzet\ShadowSocks;

use Exception;

/**
 * @method static array|null version()
 * @method static array|null list()
 * @method static array|null flow(?array $options = null) ['startTime' => 0, 'endTime' => time(), 'clear' => true]
 * @method static array|null add(string $port, string $password)
 * @method static array|null pwd(string $port, string $password)
 * @method static array|null del(string $port)
 * @method static array|null ip(string $port)
 */
class Client
{
    private string $host;
    private string $port;
    private string $pass;

    public function __construct(string $address, string $password)
    {
        if (!str_contains($address, ':')) throw new Exception('Некорректный $address: ' . $address);
        [$this->host, $this->port] = explode(':', $address, 2);
        $this->pass = $password;
    }

    private function pack($data): string
    {
        // Получаем текущее время в формате Unix timestamp
        $now = time();
        // Преобразуем время в шестнадцатеричный формат
        $timeBuffer = dechex($now);
        // Кодируем данные в формат JSON
        $dataBuffer = json_encode($data);
        // Вычисляем длину данных
        $length = strlen($dataBuffer) + 4 + 6;
        // Преобразуем длину в шестнадцатеричный формат
        $lengthBuffer = dechex($length);
        // Вычисляем контрольную сумму данных
        $code = substr(md5($now . $dataBuffer . $this->pass), 0, 8);
        // Упаковываем данные
        return $lengthBuffer . $timeBuffer . $dataBuffer . $code;
    }

    private function checkData($buffer)
    {
        // Если длина буфера меньше 4, возвращаем null
        if (strlen($buffer) < 4) {
            return null;
        }

        // Извлекаем длину данных из буфера
        $length = hexdec(substr($buffer, 0, 4));
        // Если длина буфера больше или равна длине данных + 4
        if (strlen($buffer) >= $length + 4) {
            // Извлекаем данные из буфера
            $data = substr($buffer, 4, $length + 4);
            // Декодируем данные из формата JSON
            return json_decode($data, true);
        } else {
            // Если длина буфера меньше длины данных + 4, возвращаем null
            return null;
        }
    }

    private function sendMessage(array $data): mixed
    {
        // Открываем сокет для связи с сервером
        $client = fsockopen($this->host, $this->port, $error_code, $error_message);
        if (!$client) {
            throw new Exception("Не могу открыть сокет: ($error_code) $error_message");
        }
        // Отправляем упакованные данные на сервер
        fwrite($client, $this->pack($data));
        // Устанавливаем таймаут для чтения данных из сокета
        stream_set_timeout($client, 10);
        $receive = '';
        // Читаем данные из сокета, пока не достигнем конца файла
        while (!feof($client)) {
            $receive .= fgets($client, 128);
        }
        // Закрываем сокет
        fclose($client);
        // Проверяем полученные данные
        $message = $this->checkData($receive);
        // Если код сообщения равен 0, возвращаем данные
        if (isset($message['code']) && $message['code'] === 0) {
            return $message['data'];
        } else {
            // В противном случае выводим сообщение об ошибке
            throw new Exception("Произошла ошибка: " . json_encode($message));
        }
    }

    public function send(array $data)
    {
        if (!isset($data['command']) || !in_array($data['command'], array_keys(Manager::COMMANDS))) {
            throw new Exception('Некорректная команда');
        }

        // Получаем все IP-адреса, связанные с хостом
        if (filter_var($this->host, FILTER_VALIDATE_IP)) {
            $ips = [$this->host];
        } else {
            $ips = gethostbynamel($this->host);
        }

        if (count($ips) === 0) {
            throw new Exception("Некорректный IP: $this->host");
        } else {
            $results = [];
            // Для каждого IP-адреса отправляем сообщение и сохраняем результат
            foreach ($ips as $ip) {
                try {
                    $results[] = $this->sendMessage($data);
                } catch (Exception $e) {
                    $results[] = null;
                }
            }

            // Обрабатываем результаты в зависимости от команды
            if ($data['command'] === 'version') {
                // Для команды 'version' собираем все версии
                $successMark = true;
                $versions = [];
                $ret = ['isGfw' => false];
                foreach ($results as $result) {
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
                // Для команды 'flow' суммируем потоки по портам
                $successMark = false;
                $flows = [];
                foreach ($results as $result) {
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
                // Для команды 'list' считаем количество портов
                $successMark = false;
                $ports = [];
                foreach ($results as $result) {
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
                    if ($info['number'] >= count($results)) {
                        $ret[] = ['port' => $port, 'password' => $info['password']];
                    }
                }
                return $successMark ? $ret : null;
            } else {
                // Для всех остальных команд возвращаем случайный результат
                $random = array_rand($results);
                return $results[$random] ?? null;
            }
        }
    }

    public function __call($method, $args)
    {
        if (in_array($method, array_keys(Manager::COMMANDS))) {
            if (count($args) < count(Manager::COMMANDS[$method])) {
                throw new Exception("Отсутствуют необходимые аргументы для команды $method");
            }
            return call_user_func_array(
                [$this, 'send'],
                ['command' => $method] + array_combine(Manager::COMMANDS[$method], $args)
            );
        } else {
            throw new Exception('Некорректная команда');
        }
    }
}