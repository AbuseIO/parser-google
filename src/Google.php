<?php

namespace AbuseIO\Parsers;

use AbuseIO\Models\Incident;

/**
 * Class Google
 * @package AbuseIO\Parsers
 */
class Google extends Parser
{
    /**
     * Create a new Google instance
     *
     * @param \PhpMimeMailParser\Parser $parsedMail phpMimeParser object
     * @param array $arfMail array with ARF detected results
     */
    public function __construct($parsedMail, $arfMail)
    {
        parent::__construct($parsedMail, $arfMail, $this);
    }

    /**
     * Parse attachments
     * @return array    Returns array with failed or success data
     *                  (See parser-common/src/Parser.php) for more info.
     */
    public function parse()
    {
        $xml       = simplexml_load_string($this->parsedMail->getMessageBody());
        $timestamp = strtotime($xml->attributes()->date);

        foreach ($xml->list as $reports) {
            $this->feedName = (string)$reports->attributes()->type;

            // If feed is known and enabled, validate data and save report
            if ($this->isKnownFeed() && $this->isEnabledFeed()) {
                foreach ($reports->url_info as $url_info) {
                    $url = (string)$url_info->attributes()->url;
                    $ip = (string)$url_info->attributes()->ip;

                    $urlData = getUrlData($url);

                    if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
                        // No IP supplied by Google
                        if (!empty($urlData['host']) &&
                            !filter_var($urlData['host'], FILTER_VALIDATE_IP) === false
                        ) {
                            // Hostname is an IP address
                            $ip = $urlData['host'];
                        } else {
                            // We have no IP address, try to get the IP address by resolving the domain
                            $ip = @gethostbyname($urlData['host']);

                            // If it fails, set to localhost
                            $ip = ($ip == $urlData['host']) ? '127.0.0.1' : $ip;
                        }
                    }

                    $report = [
                        'domain' => getDomain($url),
                        'uri' => getUri($url),
                    ];

                    // Sanity check
                    if ($this->hasRequiredFields($report) === true) {
                        // incident has all requirements met, filter and add!
                        $report = $this->applyFilters($report);

                        $incident = new Incident();
                        $incident->source      = config("{$this->configBase}.parser.name");
                        $incident->source_id   = false;
                        $incident->ip          = $ip;
                        $incident->domain      = $report['domain'];
                        $incident->class       = config("{$this->configBase}.feeds.{$this->feedName}.class");
                        $incident->type        = config("{$this->configBase}.feeds.{$this->feedName}.type");
                        $incident->timestamp   = $timestamp;
                        $incident->information = json_encode($urlData);

                        $this->incidents[] = $incident;
                    }
                }
            }
        }

        return $this->success();
    }
}
