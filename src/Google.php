<?php

namespace AbuseIO\Parsers;

use Ddeboer\DataImport\Reader;
use Ddeboer\DataImport\Writer;
use Ddeboer\DataImport\Filter;
use Illuminate\Filesystem\Filesystem;
use SplFileObject;
use Uuid;
use Log;

class Google extends Parser
{
    public $parsedMail;
    public $arfMail;

    /**
     * Create a new Google instance
     */
    public function __construct($parsedMail, $arfMail)
    {
        $this->parsedMail = $parsedMail;
        $this->arfMail = $arfMail;
    }

    /**
     * Parse attachments
     * @return Array    Returns array with failed or success data
     *                  (See parser-common/src/Parser.php) for more info.
     */
    public function parse()
    {
        Log::info(
            get_class($this). ': Received message from: '.
            $this->parsedMail->getHeader('from') . " with subject: '" .
            $this->parsedMail->getHeader('subject') . "' arrived at parser: " .
            config('parsers.Google.parser.name')
        );

        $events         = [ ] ;
        $xml            = simplexml_load_string($this->parsedMail->getMessageBody());
        $timestamp      = strtotime($xml->attributes()->date);

        foreach ($xml->list as $report) {
            $feedName = (string)$report->attributes()->type;

            if (empty(config("parsers.Google.feeds.{$feedName}"))) {
                return $this->failed(
                    "Detected feed '{$feedName}' is unknown."
                );
            }

            // If the feed is disabled, then continue on to the next feed or attachment
            // its not a 'fail' in the sense we should start alerting as it was disabled
            // by design or user configuration
            if (config("parsers.Google.feeds.{$feedName}.enabled") !== true) {
                continue;
            }

            foreach ($report->url_info as $url_info) {
                $url = (string)$url_info->attributes()->url;
                $ip = (string)$url_info->attributes()->ip;

                if (!preg_match("/((http|https)\:\/\/).*/", $url, $m)) {
                    $url = "http://${url}";
                }

                $url_info = parse_url($url);

                if (!filter_var($ip, FILTER_VALIDATE_IP) === true) {
                    // IP is within the URL we need

                    if (filter_var($url_info['host'], FILTER_VALIDATE_IP) === true) {
                        $url_info['ip'] = $url_info['host'];
                        $url_info['domain'] = '';
                    } else {
                        $url_info['ip'] = gethostbyname($url_info['host']);
                        $url_info['domain'] = $url_info['host'];
                    }
                } else {
                    $url_info['ip'] = $ip;
                    $url_info['domain'] = $url_info['host'];
                }

                if (!isset($url_info['port']) && $url_info['scheme'] == 'http') {
                    $url_info['port'] = 80;
                } elseif (!isset($url_info['port']) && $url_info['scheme'] == 'https') {
                    $url_info['port'] = 443;
                } elseif (!isset($url_info['port'])) {
                    $url_info['port'] = '';
                }

                if (!isset($url_info['path'])) {
                    $url_info['path'] = '/';
                }

                $infoBlob = array(
                    'scheme'        => $url_info['scheme'],
                    'port'          => $url_info['port'],
                    'domain'        => $url_info['domain'],
                    'uri'           => $url_info['path'],
                );

                $event = [
                    'source'        => config('parsers.Google.parser.name'),
                    'ip'            => $url_info['ip'],
                    'domain'        => $url_info['domain'],
                    'uri'           => $url_info['path'],
                    'class'         => config("parsers.Google.feeds.{$feedName}.class"),
                    'type'          => config("parsers.Google.feeds.{$feedName}.type"),
                    'timestamp'     => $timestamp,
                    'information'   => json_encode($infoBlob),
                ];

                $events[] = $event;
            }

        }

        return $this->success($events);
    }
}
