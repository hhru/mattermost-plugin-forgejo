// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

import React from 'react';
import {Tooltip, OverlayTrigger} from 'react-bootstrap';
import PropTypes from 'prop-types';
import {makeStyleFromTheme, changeOpacity} from 'mattermost-redux/utils/theme_utils';

import {RHSStates} from '../../constants';

export default class SidebarButtons extends React.PureComponent {
    static propTypes = {
        theme: PropTypes.object.isRequired,
        connected: PropTypes.bool,
        clientId: PropTypes.string,
        baseURL: PropTypes.string,
        reviews: PropTypes.arrayOf(PropTypes.object),
        unreads: PropTypes.arrayOf(PropTypes.object),
        yourPrs: PropTypes.arrayOf(PropTypes.object),
        yourAssignments: PropTypes.arrayOf(PropTypes.object),
        isTeamSidebar: PropTypes.bool,
        showRHSPlugin: PropTypes.func.isRequired,
        actions: PropTypes.shape({
            getConnected: PropTypes.func.isRequired,
            getSidebarContent: PropTypes.func.isRequired,
            updateRhsState: PropTypes.func.isRequired,
        }).isRequired,
    };

    constructor(props) {
        super(props);

        this.state = {
            refreshing: false,
        };
    }

    componentDidMount() {
        if (this.props.connected) {
            this.getData();
            return;
        }

        this.props.actions.getConnected(true);
    }

    componentDidUpdate(prevProps) {
        if (this.props.connected && !prevProps.connected) {
            this.getData();
        }
    }

    getData = async (e) => {
        if (this.state.refreshing) {
            return;
        }

        // Avoid refreshing data on each test when doing e2e testing.
        // It requires __E2E_TESTING__ env/webpack-flag set and skip_forgejo_fetch query param.
        // Otherwise we'll load app on each test consuming 3 searches from 30 rate limit.
        const params = new URLSearchParams(window.location.search);
        // eslint-disable-next-line no-undef
        if (__E2E_TESTING__ && params.get('skip_forgejo_fetch') === 'true') {
            return;
        }

        if (e) {
            e.preventDefault();
        }

        this.setState({refreshing: true});
        await this.props.actions.getSidebarContent();
        this.setState({refreshing: false});
    }

    openConnectWindow = (e) => {
        e.preventDefault();
        window.open('/plugins/forgejo/oauth/connect', 'Connect Mattermost to Forgejo', 'height=570,width=520');
    }

    openRHS = (rhsState) => {
        this.props.actions.updateRhsState(rhsState);
        this.props.showRHSPlugin();
    }

    render() {
        const style = getStyle(this.props.theme);
        const isTeamSidebar = this.props.isTeamSidebar;

        let container = style.containerHeader;
        let button = style.buttonHeader;
        let placement = 'bottom';
        if (isTeamSidebar) {
            placement = 'right';
            button = style.buttonTeam;
            container = style.containerTeam;
        }

        if (!this.props.connected) {
            if (isTeamSidebar) {
                return (
                    <OverlayTrigger
                        key='forgejoConnectLink'
                        placement={placement}
                        overlay={<Tooltip id='reviewTooltip'>{'Connect to your Forgejo'}</Tooltip>}
                    >
                        <a
                            href='/plugins/forgejo/oauth/connect'
                            onClick={this.openConnectWindow}
                            style={button}
                        >
                            <i className='fa fa-git fa-2x'/>
                        </a>
                    </OverlayTrigger>
                );
            }
            return null;
        }

        const reviews = this.props.reviews || [];
        const yourPrs = this.props.yourPrs || [];
        const unreads = this.props.unreads || [];
        const yourAssignments = this.props.yourAssignments || [];
        const refreshClass = this.state.refreshing ? ' fa-spin' : '';

        let baseURL = 'https://forgejo.pyn.ru';
        if (this.props.baseURL) {
            baseURL = this.props.baseURL;
        }

        return (
            <div style={container}>
                <a
                    key='forgejoHeader'
                    href={baseURL}
                    target='_blank'
                    rel='noopener noreferrer'
                    style={button}
                >
                    <i className='fa fa-git fa-lg'/>
                </a>
                <OverlayTrigger
                    key='forgejoYourPrsLink'
                    placement={placement}
                    overlay={<Tooltip id='yourPrsTooltip'>{'Your open pull requests'}</Tooltip>}
                >
                    <a
                        style={button}
                        onClick={() => this.openRHS(RHSStates.PRS)}
                    >
                        <i className='fa fa-compress'/>
                        {' ' + yourPrs.length}
                    </a>
                </OverlayTrigger>
                <OverlayTrigger
                    key='forgejoReviewsLink'
                    placement={placement}
                    overlay={<Tooltip id='reviewTooltip'>{'Pull requests needing review'}</Tooltip>}
                >
                    <a
                        onClick={() => this.openRHS(RHSStates.REVIEWS)}
                        style={button}
                    >
                        <i className='fa fa-code-fork'/>
                        {' ' + reviews.length}
                    </a>
                </OverlayTrigger>
                <OverlayTrigger
                    key='forgejoAssignmentsLink'
                    placement={placement}
                    overlay={<Tooltip id='reviewTooltip'>{'Your assignments'}</Tooltip>}
                >
                    <a
                        onClick={() => this.openRHS(RHSStates.ASSIGNMENTS)}
                        style={button}
                    >
                        <i className='fa fa-list-ol'/>
                        {' ' + yourAssignments.length}
                    </a>
                </OverlayTrigger>
                <OverlayTrigger
                    key='forgejoUnreadsLink'
                    placement={placement}
                    overlay={<Tooltip id='unreadsTooltip'>{'Unread messages'}</Tooltip>}
                >
                    <a
                        onClick={() => this.openRHS(RHSStates.UNREADS)}
                        style={button}
                    >
                        <i className='fa fa-envelope'/>
                        {' ' + unreads.length}
                    </a>
                </OverlayTrigger>
                <OverlayTrigger
                    key='forgejoRefreshButton'
                    placement={placement}
                    overlay={<Tooltip id='refreshTooltip'>{'Refresh'}</Tooltip>}
                >
                    <a
                        href='#'
                        style={button}
                        onClick={this.getData}
                    >
                        <i className={'fa fa-refresh' + refreshClass}/>
                    </a>
                </OverlayTrigger>
            </div>
        );
    }
}

const getStyle = makeStyleFromTheme((theme) => {
    return {
        buttonTeam: {
            color: changeOpacity(theme.sidebarText, 0.6),
            display: 'block',
            marginBottom: '10px',
            width: '100%',
        },
        buttonHeader: {
            color: changeOpacity(theme.sidebarText, 0.6),
            textAlign: 'center',
            cursor: 'pointer',
        },
        containerHeader: {
            marginTop: '10px',
            marginBottom: '5px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-around',
            padding: '0 10px',
        },
        containerTeam: {
        },
    };
});
