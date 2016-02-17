<?php

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
            'type'      => 'ABUSE',
            'enabled'   => true,
            'fields'    => [
                'domain',
                'uri',
            ],
        ],

        '1' => [
            'class'     => 'PHISING_WEBSITE',
            'type'      => 'ABUSE',
            'enabled'   => true,
            'fields'    => [
                'domain',
                'uri',
            ],
        ],

        '2' => [
            'class'     => 'DISTRIBUTION_WEBSITE',
            'type'      => 'ABUSE',
            'enabled'   => true,
            'fields'    => [
                'domain',
                'uri',
            ],
        ],

    ],
];
