<?php
/*
 * Google currently known list types:
 *
 * 0: Compromised
 * 1: Social Engineering
 * 2: Distribution
 * 3: Unwanted Software
 * 4: Malicious Software
 *
 * Original Google XML schema can be found at:
 * http://www.google.com/safebrowsing/alerts/xml/message.xsd
 */
return [
    'parser' => [
        'name'          => 'Google Safe Browsing',
        'enabled'       => true,
        'sender_map'    => [
            '/noreply@google.com/',
        ],
        'body_map'      => [
            //
        ],
    ],

    'feeds' => [
        '0' => [
            'class'     => 'COMPROMISED_WEBSITE',
            'category'  => 'Compromised Website',
            'type'      => 'ABUSE',
            'enabled'   => true,
            'fields'    => [
                'domain',
                'uri',
            ],
        ],

        '1' => [
            'class'     => 'PHISING_WEBSITE',
            'category'  => 'Website for Social Engineering',
            'type'      => 'ABUSE',
            'enabled'   => true,
            'fields'    => [
                'domain',
                'uri',
            ],
        ],

        '2' => [
            'class'     => 'DISTRIBUTION_WEBSITE',
            'category'  => 'Website for Distribution',
            'type'      => 'ABUSE',
            'enabled'   => true,
            'fields'    => [
                'domain',
                'uri',
            ],
        ],

        '3' => [
            'class'     => 'DISTRIBUTION_WEBSITE',
            'category'  => 'Website for Unwanted Software',
            'type'      => 'ABUSE',
            'enabled'   => true,
            'fields'    => [
                'domain',
                'uri',
            ],
        ],

        '4' => [
            'class'     => 'DISTRIBUTION_WEBSITE',
            'category'  => 'Website for Malicious Software',
            'type'      => 'ABUSE',
            'enabled'   => true,
            'fields'    => [
                'domain',
                'uri',
            ],
        ],

    ],
];
