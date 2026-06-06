// Copyright (c) 2018-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

import {connect} from 'react-redux';
import {Dispatch, bindActionCreators} from 'redux';

import {UserProfile} from '@mattermost/types/users';

import {getPluginState} from '../../selectors';

import {GlobalState} from '../../types/store';

import {getForgejoUser} from '../../actions';

import {UserAttribute} from './user_attribute';

type OwnProps = {
    user: UserProfile;
};

type StateProps = {
    id: string;
    username?: string;
    baseURL: string;
}

function mapStateToProps(state: GlobalState, ownProps: OwnProps): StateProps {
    const mmUserId = ownProps.user ? ownProps.user.id : '';

    const pluginState = getPluginState(state);
    const forgejoUser = pluginState.forgejoUsers[mmUserId];

    return {
        id: mmUserId,
        username: forgejoUser?.username,
        baseURL: pluginState.baseURL,
    };
}

function mapDispatchToProps(dispatch: Dispatch) {
    return {
        actions: bindActionCreators({
            getForgejoUser,
        }, dispatch),
    };
}

type DispatchProps = ReturnType<typeof mapDispatchToProps>;

export type Props = OwnProps & StateProps & DispatchProps;

export default connect(mapStateToProps, mapDispatchToProps)(UserAttribute);
