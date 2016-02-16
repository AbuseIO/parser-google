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
                foreach ($reports->url_info as $report) {
                    $url = (string)$report->attributes()->url;
                    $ip = (string)$report->attributes()->ip;

                    if (!preg_match("/((http|https)\:\/\/).*/", $url, $m)) {
                        $url = "http://${url}";
                    }

                    $report = parse_url($url);

                    if (!filter_var($ip, FILTER_VALIDATE_IP) === true) {
                        // IP is within the URL we need

                        if (!filter_var($report['host'], FILTER_VALIDATE_IP) === false) {
                            $report['ip'] = $report['host'];
                            $report['domain'] = false;
                        } else {
                            $resolved = gethostbyname($report['host']);
                            if ($resolved != $report['host']) {
                                $report['ip'] = gethostbyname($report['host']);
                            } else {
                                $report['ip'] = '127.0.0.1';
                            }
                            $report['domain'] = $report['host'];
                        }
                    } else {
                        $report['ip'] = $ip;
                        $report['domain'] = $report['host'];
                    }

                    if (!isset($report['port']) && $report['scheme'] == 'http') {
                        $report['port'] = 80;
                    } elseif (!isset($report['port']) && $report['scheme'] == 'https') {
                        $report['port'] = 443;
                    } elseif (!isset($report['port'])) {
                        $report['port'] = '';
                    }

                    if (!isset($report['path'])) {
                        $report['path'] = '/';
                    }

                    if (preg_match(
                        "/[a-z0-9\-]{1,63}\.[a-z\.]{2,6}$/",
                        parse_url(
                            'http://'.$report['domain'],
                            PHP_URL_HOST
                        ),
                        $_domain_tld
                    )) {
                        $report['domain'] = $_domain_tld[0];
                    }

                    // Sanity check
                    if ($this->hasRequiredFields($report) === true) {
                        // incident has all requirements met, filter and add!
                        $report = $this->applyFilters($report);

                        // If the domain is filled with an IP, we can keep the URI, but we dont consider it
                        // as a domain, else we'd be using ip contacts for domain names.
                        if (empty($report['domain']) || !filter_var($report['domain'], FILTER_VALIDATE_IP) === false) {
                            $report['domain'] = false;
                        }

                        $infoBlob = $this->applyFilters(
                            array(
                                'scheme'        => $report['scheme'],
                                'port'          => $report['port'],
                                'domain'        => $report['domain'],
                                'uri'           => $report['path'],
                                'url'           => $url,
                            )
                        );

                        $incident = new Incident();
                        $incident->source      = config("{$this->configBase}.parser.name");
                        $incident->source_id   = false;
                        $incident->ip          = $report['ip'];
                        $incident->domain      = $report['domain'];
                        $incident->uri         = $report['path'];
                        $incident->class       = config("{$this->configBase}.feeds.{$this->feedName}.class");
                        $incident->type        = config("{$this->configBase}.feeds.{$this->feedName}.type");
                        $incident->timestamp   = $timestamp;
                        $incident->information = json_encode($infoBlob);

                        $this->incidents[] = $incident;
                    }
                }
            }
        }

        return $this->success();
    }
}
