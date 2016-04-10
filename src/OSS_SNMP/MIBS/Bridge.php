<?php

/*
    Copyright (c) 2012, Open Source Solutions Limited, Dublin, Ireland
    All rights reserved.

    Contact: Barry O'Donovan - barry (at) opensolutions (dot) ie
             http://www.opensolutions.ie/

    This file is part of the OSS_SNMP package.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are met:

        * Redistributions of source code must retain the above copyright
          notice, this list of conditions and the following disclaimer.
        * Redistributions in binary form must reproduce the above copyright
          notice, this list of conditions and the following disclaimer in the
          documentation and/or other materials provided with the distribution.
        * Neither the name of Open Source Solutions Limited nor the
          names of its contributors may be used to endorse or promote products
          derived from this software without specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
    ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
    WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
    DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY
    DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
    (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
    LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
    ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
    (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
    SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

namespace OSS_SNMP\MIBS;

/**
 * A class for performing SNMP V2 queries on generic devices
 *
 * @copyright Copyright (c) 2012, Open Source Solutions Limited, Dublin, Ireland
 * @author Barry O'Donovan <barry@opensolutions.ie>
 */
class Bridge extends \OSS_SNMP\MIB
{
    const OID_BRIDGE_BASE_PORT_IF_INDEX    = '.1.3.6.1.2.1.17.1.4.1.2';

	const OID_BRIDGE_MAC_ADDRESS           = '.1.3.6.1.2.1.17.4.3.1.1';
	const OID_BRIDGE_MAC_ADDRESS_BASE_PORT = '.1.3.6.1.2.1.17.4.3.1.2';

    /**
     * Returns an associate array of STP port IDs (key) to interface IDs (value)
     *
     * e.g.  [22] => 10122
     *
     *
     * @return array Associate array of STP port IDs (key) to interface IDs (value)
     */
    public function basePortIfIndexes()
    {
        return $this->getSNMP()->walk1d( self::OID_BRIDGE_BASE_PORT_IF_INDEX );
    }
    
    /**
     * Returns array Associative MAC ADDRESSES (value) to unique index (key)
     *
     * e.g.	[0.0.136.54.152.12] => 000075334E92
     *
     * @return array Associative MAC ADDRESSES (value) to unique index (key)
     */
    public function macAddressList() {
		return $this->getSNMP()->subOidWalk( self::OID_BRIDGE_MAC_ADDRESS, 12, -1 );
	}
	
	/**
	 * Returns array Associative of BasePort (value) to unique index (key)
	 * for mac address listed in self::macAddressList()
     *  Use basePortIfIndexes to obtain interface
     *
     * e.g.	[0.0.136.54.152.12] => 2
     *
     *
     * @return array Associative of BasePort (value) to unique index (key)
     *   for mac address listed in self::macAddressList()
     */
    public function macAddressBasePort() {
		return $this->getSNMP()->subOidWalk( self::OID_BRIDGE_MAC_ADDRESS_BASE_PORT, 12, -1 );
	}
	

}
