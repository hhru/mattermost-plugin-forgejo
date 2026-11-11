// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

import React from 'react';
import PropTypes from 'prop-types';
import Scrollbars from 'react-custom-scrollbars-2';
import {OverlayTrigger, Tooltip} from 'react-bootstrap';

import {makeStyleFromTheme, changeOpacity} from 'mattermost-redux/utils/theme_utils';

import {RHSStates} from '../../constants';

import ForgejoItems from './forgejo_items';

const getStyle = makeStyleFromTheme((theme) => {
    return {
        sectionHeader: {
            padding: '15px',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
        },
        refreshButton: {
            color: changeOpacity(theme.centerChannelColor, 0.6),
            cursor: 'pointer',
            background: 'transparent',
            border: 'none',
            padding: 0,
        },
    };
});

export function renderView(props) {
    return (
        <div
            {...props}
            className='scrollbar--view'
        />
    );
}

export function renderThumbHorizontal(props) {
    return (
        <div
            {...props}
            className='scrollbar--horizontal'
        />
    );
}

export function renderThumbVertical(props) {
    return (
        <div
            {...props}
            className='scrollbar--vertical'
        />
    );
}

function mapForgejoItemListToPrList(gilist) {
    if (!gilist) {
        return [];
    }

    return gilist.map((pr) => {
        return {url: pr.repository_url, number: pr.number};
    });
}

function shouldUpdateDetails(prs, prevPrs, targetState, currentState, prevState) {
    if (currentState === targetState) {
        if (currentState !== prevState) {
            return true;
        }

        if (prs.length !== prevPrs.length) {
            return true;
        }

        for (let i = 0; i < prs.length; i++) {
            if (prs[i].id !== prevPrs[i].id) {
                return true;
            }
        }
    }

    return false;
}

export default class SidebarRight extends React.PureComponent {
    static propTypes = {
        orgs: PropTypes.array.isRequired,
        baseURL: PropTypes.string,
        reviews: PropTypes.arrayOf(PropTypes.object),
        unreads: PropTypes.arrayOf(PropTypes.object),
        yourPrs: PropTypes.arrayOf(PropTypes.object),
        yourAssignments: PropTypes.arrayOf(PropTypes.object),
        rhsState: PropTypes.string,
        reviewTargetDays: PropTypes.number,
        reviewTargetDayType: PropTypes.string,
        theme: PropTypes.object.isRequired,
        actions: PropTypes.shape({
            getYourPrsDetails: PropTypes.func.isRequired,
            getReviewsDetails: PropTypes.func.isRequired,
            getSidebarContent: PropTypes.func.isRequired,
        }).isRequired,
    };

    constructor(props) {
        super(props);
        this.state = {refreshing: false};
        this.mounted = false;
        this.refreshing = false;
    }

    componentDidMount() {
        this.mounted = true;

        if (this.props.yourPrs && this.props.rhsState === RHSStates.PRS) {
            this.props.actions.getYourPrsDetails(mapForgejoItemListToPrList(this.props.yourPrs));
        }

        if (this.props.reviews && this.props.rhsState === RHSStates.REVIEWS) {
            this.props.actions.getReviewsDetails(mapForgejoItemListToPrList(this.props.reviews));
        }
    }

    componentWillUnmount() {
        this.mounted = false;
    }

    handleRefresh = async (e) => {
        if (e) {
            e.preventDefault();
        }
        if (this.refreshing) {
            return;
        }
        this.refreshing = true;
        this.setState({refreshing: true});
        try {
            await this.props.actions.getSidebarContent();
        } finally {
            this.refreshing = false;
            if (this.mounted) {
                this.setState({refreshing: false});
            }
        }
    };

    componentDidUpdate(prevProps) {
        if (shouldUpdateDetails(this.props.yourPrs, prevProps.yourPrs, RHSStates.PRS, this.props.rhsState, prevProps.rhsState)) {
            this.props.actions.getYourPrsDetails(mapForgejoItemListToPrList(this.props.yourPrs));
        }

        if (shouldUpdateDetails(this.props.reviews, prevProps.reviews, RHSStates.REVIEWS, this.props.rhsState, prevProps.rhsState)) {
            this.props.actions.getReviewsDetails(mapForgejoItemListToPrList(this.props.reviews));
        }
    }

    render() {
        const style = getStyle(this.props.theme);
        const baseURL = this.props.baseURL ? this.props.baseURL : 'https://forgejo.pyn.ru';
        let orgQuery = '';
        this.props.orgs.map((org) => {
            orgQuery += ('+org%3A' + org);
            return orgQuery;
        });
        const {yourPrs, reviews, unreads, yourAssignments, rhsState} = this.props;

        let title = '';
        let forgejoItems = [];
        let listUrl = '';

        switch (rhsState) {
        case RHSStates.PRS:

            forgejoItems = yourPrs;
            title = 'Your Open Pull Requests';
            listUrl = baseURL + '/pulls?type=created_by&sort=recentupdate&state=open&q=&fuzzy=true';

            break;
        case RHSStates.REVIEWS:

            forgejoItems = reviews;
            listUrl = baseURL + '/pulls?type=review_requested&sort=recentupdate&state=open&q=&fuzzy=true';
            title = 'Pull Requests Needing Review';

            break;
        case RHSStates.UNREADS:

            forgejoItems = unreads;
            title = 'Unread Messages';
            listUrl = baseURL + '/notifications';
            break;
        case RHSStates.ASSIGNMENTS:

            forgejoItems = yourAssignments;
            title = 'Your Assignments';
            listUrl = baseURL + '/pulls?type=assigned&sort=recentupdate&state=open&q=&fuzzy=true';
            break;
        default:
            break;
        }

        return (
            <React.Fragment>
                <Scrollbars
                    autoHide={true}
                    autoHideTimeout={500}
                    autoHideDuration={500}
                    renderThumbHorizontal={renderThumbHorizontal}
                    renderThumbVertical={renderThumbVertical}
                    renderView={renderView}
                >
                    <div style={style.sectionHeader}>
                        <strong>
                            <a
                                href={listUrl}
                                target='_blank'
                                rel='noopener noreferrer'
                            >{title}</a>
                        </strong>
                        <OverlayTrigger
                            key='rhsRefreshButton'
                            placement='left'
                            overlay={<Tooltip id='rhsRefreshTooltip'>{'Refresh'}</Tooltip>}
                        >
                            <button
                                type='button'
                                aria-label='Refresh'
                                style={style.refreshButton}
                                onClick={this.handleRefresh}
                            >
                                <i className={'fa fa-refresh' + (this.state.refreshing ? ' fa-spin' : '')}/>
                            </button>
                        </OverlayTrigger>
                    </div>
                    <div>
                        <ForgejoItems
                            items={forgejoItems}
                            theme={this.props.theme}
                            showReviewSLA={rhsState === RHSStates.REVIEWS}
                            reviewTargetDays={this.props.reviewTargetDays || 0}
                            reviewTargetDayType={this.props.reviewTargetDayType || 'calendar'}
                        />
                    </div>
                </Scrollbars>
            </React.Fragment>
        );
    }
}
