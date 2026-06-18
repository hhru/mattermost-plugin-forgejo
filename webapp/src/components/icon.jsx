// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

import React from 'react';
import PropTypes from 'prop-types';

export default class ForgejoIcon extends React.PureComponent {
    static propTypes = {
        type: PropTypes.oneOf([
            'menu',
        ]),
    };

    static defaultProps = {
        type: 'menu',
    };

    render() {
        let iconStyle = {};
        if (this.props.type === 'menu') {
            iconStyle = {flex: '0 0 auto', width: '20px', height: '20px', borderRadius: '50px', padding: '2px'};
        }

        return (
            <span className='MenuItem__icon'>
                <svg
                    aria-hidden='true'
                    focusable='false'
                    role='img'
                    viewBox='0 0 212 212'
                    width='14'
                    height='14'
                    style={iconStyle}
                >
                    <g
                        transform='translate(6,6)'
                        fill='none'
                    >
                        <path
                            d='M58 168 v-98 a50 50 0 0 1 50-50 h20'
                            stroke='#ff6600'
                            strokeWidth='25'
                        />
                        <path
                            d='M58 168 v-30 a50 50 0 0 1 50-50 h20'
                            stroke='#d40000'
                            strokeWidth='25'
                        />
                        <circle
                            cx='142'
                            cy='20'
                            r='18'
                            stroke='#ff6600'
                            strokeWidth='15'
                        />
                        <circle
                            cx='142'
                            cy='88'
                            r='18'
                            stroke='#d40000'
                            strokeWidth='15'
                        />
                        <circle
                            cx='58'
                            cy='180'
                            r='18'
                            stroke='#d40000'
                            strokeWidth='15'
                        />
                    </g>
                </svg>
            </span>
        );
    }
}
