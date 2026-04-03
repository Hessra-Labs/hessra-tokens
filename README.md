# hessra-tokens

This repository contains the open source (Apache-2.0) primitives for the Hessra capability security model.

Capability security is a security model to manage how objects perform actions on other objects. An object (i.e. subject) must present a *capability* to their target object (i.e. resource) with their request. This capability is all the proof that is needed in order for the request to proceed.

A capability is made up of two things: the authority to perform the action and the designation or the complete, unambiguous name of what it is acting on. While not strictly necessary in the model, Hessra capabilities also include the operation (e.g. read/write) for the action.

These primitives are built on [biscuits](https://www.biscuitsec.org/) and are opinionated implementations for a capability security model meant for distributed systems.

This repository contains code for three primitives able to be used in conjunction with one another.

## hessra-identity-token

A token used to encode identity of an object. The primary feature is an embedded offline, delegatable heirarchy using URI:URNs. For example, you can mint an identity token with the identity `bob` and then create a delegated identity from it for something underneath such as `bob:agent` or `webapp:user123`.

## hessra-cap-token

This is the capability token meant to be used to authorize requests in a capability security model. They contain the subject, resource, and operation allowed for the request. These tokens support composition through the use of designation via biscuit attenuation.

## hessra-context-token

Context tokens are meant to hold data labels. These are optional to use and are meant to accrue as actions are taken. Then, the context tokens can be used to help make authorization decisions before minting new capabilities.