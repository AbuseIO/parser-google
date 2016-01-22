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
            'type'      => 'Abuse',
            'enabled'   => true,
            'fields'    => [
                'scheme',
                'port',
                'domain',
                'path',
            ],
        ],

        '1' => [
            'class'     => 'PHISING_WEBSITE',
            'type'      => 'Abuse',
            'enabled'   => true,
            'fields'    => [
                'scheme',
                'port',
                'domain',
                'path',
            ],
        ],

        '2' => [
            'class'     => 'DISTRIBUTION_WEBSITE',
            'type'      => 'Abuse',
            'enabled'   => true,
            'fields'    => [
                'scheme',
                'port',
                'domain',
                'path',
            ],
        ],

    ],
];
