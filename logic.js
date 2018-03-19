/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

'use strict';

/**
 * A Member grants access to their record to another Member.
 * @param {org.degree.ucsd.AuthorizeAccess} authorize - the authorize to be processed
 * @transaction
 */
function authorizeAccess(authorize) {

    var me = getCurrentParticipant();
    console.log('**** AUTH: ' + me.getIdentifier() + ' granting access to ' + authorize.memberId);

    if (!me) {
        throw new Error('A participant/certificate mapping does not exist.');
    }

    // if the member is not already authorized, we authorize them
    var index = -1;

    if (!me.authorized) {
        me.authorized = [];
    }
    else {
        index = me.authorized.indexOf(authorize.memberId);
    }

    if (index < 0) {
        me.authorized.push(authorize.memberId);

        return getParticipantRegistry('org.degree.ucsd.Member')
            .then(function (memberRegistry) {

                // emit an event
                var event = getFactory().newEvent('org.degree.ucsd', 'MemberEvent');
                event.memberTransaction = authorize;
                emit(event);

                // persist the state of the member
                return memberRegistry.update(me);
            });
    }
}

/**
 * A Member revokes access to their record from another Member.
 * @param {org.degree.ucsd.RevokeAccess} revoke - the RevokeAccess to be processed
 * @transaction
 */
function revokeAccess(revoke) {

    var me = getCurrentParticipant();
    console.log('**** REVOKE: ' + me.getIdentifier() + ' revoking access to ' + revoke.memberId);

    if (!me) {
        throw new Error('A participant/certificate mapping does not exist.');
    }

    // if the member is authorized, we remove them
    var index = me.authorized ? me.authorized.indexOf(revoke.memberId) : -1;

    if (index > -1) {
        me.authorized.splice(index, 1);

        return getParticipantRegistry('org.degree.ucsd.Member')
            .then(function (memberRegistry) {

                // emit an event
                var event = getFactory().newEvent('org.degree.ucsd', 'MemberEvent');
                event.memberTransaction = revoke;
                emit(event);

                // persist the state of the member
                return memberRegistry.update(me);
            });
    }
}

/**
 * A Member grants access to their Degree assets
 * @param {org.degree.ucsd.AuthorizeDegreeAccess} transaction - authorize transaction
 * @transaction
 */
function authorizeDegreeAccess(transaction) {
    var me = getCurrentParticipant();

    if (me == null) {
        throw new Error("A participant/certificate mapping does not exist");
    }

    var requestorId = transaction.memberId;
    if (requestorId == null) {
        throw new Error("Invalid request. \"memberId\" should be defined");
    }

    var myId = me.getIdentifier();
    console.log("Member " + myId + " grants \"Degree\" access to " + requestorId);

    return query("getDegreeByMemberId", { memberId: myId })
        .then(function (records) {
            if (records.length > 0) {
                var serializer = getSerializer();
                var degree = serializer.toJSON(records[0]);

                if (!Array.isArray(degree.authorized)) {
                    degree.authorized = [];
                }

                if (degree.authorized.indexOf(requestorId) < 0) {
                    degree.authorized.push(requestorId);

                    return getAssetRegistry("org.degree.ucsd.Degree")
                        .then(function (registry) { registry.update(serializer.fromJSON(degree)) })
                        .then(function () {
                            var event = getFactory().newEvent('org.degree.ucsd', 'DegreeEvent');
                            event.degreeTransaction = transaction;
                            emit(event);
                        });
                }
            }
        })
        .catch(function (ex) { console.error(ex); throw ex; });
}

/**
 * A Member revokes access to their Degree assets
 * @param {org.degree.ucsd.RevokeDegreeAccess} transaction - revoke transaction
 * @transaction
 */
function revokeDegreeAccess(transaction) {
    var me = getCurrentParticipant();

    if (me == null) {
        throw new Error("A participant/certificate mapping does not exist");
    }

    var requestorId = transaction.memberId;
    if (requestorId == null) {
        throw new Error("Invalid request. \"memberId\" should be defined");
    }

    var myId = me.getIdentifier();
    console.log("Member " + myId + " grants \"Degree\" access to " + requestorId);

    return query("getDegreeByMemberId", { memberId: myId })
        .then(function (records) {
            if (records.length > 0) {
                var serializer = getSerializer();
                var degree = serializer.toJSON(records[0]);

                if (Array.isArray(degree.authorized)) {
                    var index = degree.authorized.indexOf(requestorId);

                    if (index >= 0) {
                        degree.authorized.splice(index, 1);

                        return getAssetRegistry("org.degree.ucsd.Degree")
                            .then(function (registry) { registry.update(serializer.fromJSON(degree)) })
                            .then(function () {
                                var event = getFactory().newEvent('org.degree.ucsd', 'DegreeEvent');
                                event.degreeTransaction = transaction;
                                emit(event);
                            });
                    }
                }
            }
        })
        .catch(function (ex) { console.error(ex); throw ex; });
}
