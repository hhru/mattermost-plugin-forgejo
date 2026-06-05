// Copyright (c) 2018-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

import React from 'react';

import {useMount} from '../../hooks/useMount';

import type {Props} from '.';

export const UserAttribute = (props: Props) => {
    useMount(() => {
        props.actions.getForgejoUser(props.id);
    });

    const username = props.username;
    if (!username) {
        return null;
    }

    let baseURL = 'https://forgejo.pyn.ru';
    if (props.baseURL) {
        baseURL = props.baseURL;
    }

    return (
        <div style={style.container}>
            <a
                href={baseURL + '/' + username}
                target='_blank'
                rel='noopener noreferrer'
            >
                <i className='fa fa-git'/>{' ' + username}
            </a>
        </div>
    );
};

const style = {
    container: {
        margin: '5px 0',
    },
};
