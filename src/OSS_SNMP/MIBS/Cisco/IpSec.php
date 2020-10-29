<?php

/*
    Copyright (c) 2012 - 2013, Open Source Solutions Limited, Dublin, Ireland
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

namespace OSS_SNMP\MIBS\Cisco;

/**
 * A class for performing SNMP V2 queries on Cisco devices
 *
 * @copyright Copyright (c) 2012 - 2013, Open Source Solutions Limited, Dublin, Ireland
 * @author Barry O'Donovan <barry@opensolutions.ie>
 */
class IpSec extends \OSS_SNMP\MIBS\Cisco
{

    const OID_CIKE_PEER_COOR_IPSEC_TUN_INDEX = '.1.3.6.1.4.1.9.9.171.1.2.4.1.7';
    const OID_CIKE_PEER_COOR_IPSEC_TUN_IKE_TUN_INDEX = '.1.3.6.1.4.1.9.9.171.1.3.2.1.2.';
    const OID_CIKE_PEER_COOR_IPSEC_TUN_IKE_TUN_LOCAL_VALUE = '.1.3.6.1.4.1.9.9.171.1.2.3.1.3.';
    const OID_CIKE_PEER_COOR_IPSEC_TUN_IKE_TUN_REMOTE_VALUE = '.1.3.6.1.4.1.9.9.171.1.2.3.1.7.';
    const OID_CIKE_PEER_COOR_IPSEC_TUN_IKE_TUN_HASH_ALGO = '.1.3.6.1.4.1.9.9.171.1.2.3.1.13';
    const OID_CIKE_PEER_COOR_IPSEC_TUN_IKE_TUN_ENCRYPT_ALGO = '.1.3.6.1.4.1.9.9.171.1.2.3.1.12';
    const OID_CIKE_PEER_COOR_IPSEC_TUN_IKE_TUN_HELLMAN_ALGO = '.1.3.6.1.4.1.9.9.171.1.2.3.1.11';

    /**
     * Returns the list of IpSec Tunnel Index.
     *
     * @return int[] The list of IpSec Tunnel Index
     */
    public function ipSecTunnelIndex()
    {
        $values = $this->getSNMP()->realWalk(self::OID_CIKE_PEER_COOR_IPSEC_TUN_INDEX);
        $returnArray = [];
        $index = 0;
        foreach ($values as $value){
            $tunnelIndex = substr($value, 9)+0;
            $returnArray[$index] = $tunnelIndex;
            $index++;
        }
        return $returnArray;
    }

    /**
     * TODO
     *
     * @return int TODO
     */
    public function cipSecTunIkeTunnelIndex($tunnelIndex)
    {
        return $this->getSNMP()->get(self::OID_CIKE_PEER_COOR_IPSEC_TUN_IKE_TUN_INDEX.$tunnelIndex);
    }

    /**
     * TODO
     *
     * @return int TODO
     */
    public function cikeTunLocalValue($tunnelIndex)
    {
        return $this->getSNMP()->get(self::OID_CIKE_PEER_COOR_IPSEC_TUN_IKE_TUN_LOCAL_VALUE.$tunnelIndex);
    }

    /**
     * TODO
     *
     * @return int TODO
     */
    public function cikeTunRemoteValue($tunnelIndex)
    {
        return $this->getSNMP()->get(self::OID_CIKE_PEER_COOR_IPSEC_TUN_IKE_TUN_REMOTE_VALUE.$tunnelIndex);
    }

    /**
     * Constants for possible values of hash algo
     */
    const IPSEC_HASH_ALGO_SHA1 = 3;
    const IPSEC_HASH_ALGO_SHA256 = 7;
    const IPSEC_HASH_ALGO_SHA512 = 9;

    /**
     * Text representation of Hash algorythms
     *
     * @var array Text representation of Hash algorithms
     */
    public static $IPSEC_HASH_ALGO_TYPES = array(
        self::IPSEC_HASH_ALGO_SHA1 => 'SHA1',
        self::IPSEC_HASH_ALGO_SHA256 => 'SHA256',
        self::IPSEC_HASH_ALGO_SHA512 => 'SHA512'
    );

    /**
     * TODO
     *
     * @return int[] TODO
     */
    public function cikeTunHashAlgo($translate = false)
    {
        $types = $this->getSNMP()->realWalk(self::OID_CIKE_PEER_COOR_IPSEC_TUN_IKE_TUN_HASH_ALGO);

        if( !$translate )
            return $types;

        return $this->getSNMP()->translate( $types, self::$IPSEC_HASH_ALGO_TYPES);
    }

    /**
     * Constants for possible values of encryption algo
     */
    const IPSEC_ENCRYPT_ALGO_3DES = 3;
    const IPSEC_ENCRYPT_ALGO_AES = 6;

    /**
     * Text representation of encryption algorythms
     *
     * @var array Text representation of encryption algorithms
     */
    public static $IPSEC_ENCRYPT_ALGO_TYPES = array(
        self::IPSEC_ENCRYPT_ALGO_3DES => '3DES-168',
        self::IPSEC_ENCRYPT_ALGO_AES => 'AES-256'
    );

    /**
     * TODO
     *
     * @return int[] TODO
     */
    public function cikeTunEncryptAlgo($translate = false)
    {
        $types = $this->getSNMP()->realWalk(self::OID_CIKE_PEER_COOR_IPSEC_TUN_IKE_TUN_ENCRYPT_ALGO);

        if( !$translate )
            return $types;

        return $this->getSNMP()->translate( $types, self::$IPSEC_ENCRYPT_ALGO_TYPES);
    }

    /**
     * Constants for possible values of Hellman algo
     */
    const IPSEC_HELLMAN_ALGO_GRP5 = 4;
    const IPSEC_HELLMAN_ALGO_GRP14 = 5;
    const IPSEC_HELLMAN_ALGO_GRP19 = 9;
    const IPSEC_HELLMAN_ALGO_GRP20 = 10;
    const IPSEC_HELLMAN_ALGO_GRP21 = 11;

    /**
     * Text representation of Hellman algorythms
     *
     * @var array Text representation of Hellman algorithms
     */
    public static $IPSEC_HELLMAN_ALGO_TYPES = array(
        self::IPSEC_HELLMAN_ALGO_GRP5 => 'Group 5',
        self::IPSEC_HELLMAN_ALGO_GRP14 => 'Group 14',
        self::IPSEC_HELLMAN_ALGO_GRP19 => 'Group 19',
        self::IPSEC_HELLMAN_ALGO_GRP20 => 'Group 20',
        self::IPSEC_HELLMAN_ALGO_GRP21 => 'Group 21'
    );

    /**
     * TODO
     *
     * @return int[] TODO
     */
    public function cikeTunDiffHellmanGrp($translate = false)
    {
        $types = $this->getSNMP()->realWalk(self::OID_CIKE_PEER_COOR_IPSEC_TUN_IKE_TUN_HELLMAN_ALGO);

        if( !$translate )
            return $types;

        return $this->getSNMP()->translate( $types, self::$IPSEC_HELLMAN_ALGO_TYPES);
    }
}
