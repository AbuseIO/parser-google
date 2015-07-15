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
            'class'     => 'Compromised website',
            'type'      => 'Abuse',
            'enabled'   => true,
            'fields'    => [
                //
            ],
        ],

        '1' => [
            'class'     => 'Phishing website',
            'type'      => 'Abuse',
            'enabled'   => true,
            'fields'    => [
                //
            ],
        ],

        '2' => [
            'class'     => 'Distribution website',
            'type'      => 'Abuse',
            'enabled'   => true,
            'fields'    => [
                //
            ],
        ],

    ],
];
