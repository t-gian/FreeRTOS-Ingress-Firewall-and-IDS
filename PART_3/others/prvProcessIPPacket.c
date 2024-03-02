/**
 * @brief Process an IP-packet.
 *
 * @param[in] pxIPPacket The IP packet to be processed.
 * @param[in] pxNetworkBuffer The networkbuffer descriptor having the IP packet.
 *
 * @return An enum to show whether the packet should be released/kept/processed etc.
 */

static eFrameProcessingResult_t prvProcessIPPacket( const IPPacket_t * pxIPPacket,
                                                    NetworkBufferDescriptor_t * const pxNetworkBuffer )
{
    eFrameProcessingResult_t eReturn;
    UBaseType_t uxHeaderLength = ipSIZE_OF_IPv4_HEADER;
    uint8_t ucProtocol = 0U;

    #if ( ipconfigUSE_IPv6 != 0 )
        const IPHeader_IPv6_t * pxIPHeader_IPv6 = NULL;
    #endif /* ( ipconfigUSE_IPv6 != 0 ) */

    #if ( ipconfigUSE_IPv4 != 0 )
        const IPHeader_t * pxIPHeader = &( pxIPPacket->xIPHeader );
    #endif /* ( ipconfigUSE_IPv4 != 0 ) */

    switch( pxIPPacket->xEthernetHeader.usFrameType )
    {
        #if ( ipconfigUSE_IPv6 != 0 )
            case ipIPv6_FRAME_TYPE:

                if( pxNetworkBuffer->xDataLength < sizeof( IPPacket_IPv6_t ) )
                {
                    /* The packet size is less than minimum IPv6 packet. */
                    eReturn = eReleaseBuffer;
                }
                else
                {
                    /* MISRA Ref 11.3.1 [Misaligned access] */
                    /* More details at: https://github.com/FreeRTOS/FreeRTOS-Plus-TCP/blob/main/MISRA.md#rule-113 */
                    /* coverity[misra_c_2012_rule_11_3_violation] */
                    pxIPHeader_IPv6 = ( ( const IPHeader_IPv6_t * ) &( pxNetworkBuffer->pucEthernetBuffer[ ipSIZE_OF_ETH_HEADER ] ) );

                    uxHeaderLength = ipSIZE_OF_IPv6_HEADER;
                    ucProtocol = pxIPHeader_IPv6->ucNextHeader;
                    /* MISRA Ref 11.3.1 [Misaligned access] */
                    /* More details at: https://github.com/FreeRTOS/FreeRTOS-Plus-TCP/blob/main/MISRA.md#rule-113 */
                    /* coverity[misra_c_2012_rule_11_3_violation] */
                    eReturn = prvAllowIPPacketIPv6( ( ( const IPHeader_IPv6_t * ) &( pxIPPacket->xIPHeader ) ), pxNetworkBuffer, uxHeaderLength );

                    /* The IP-header type is copied to a special reserved location a few bytes before the message
                     * starts. In the case of IPv6, this value is never actually used and the line below can safely be removed
                     * with no ill effects. We only store it to help with debugging. */
                    pxNetworkBuffer->pucEthernetBuffer[ 0 - ( BaseType_t ) ipIP_TYPE_OFFSET ] = pxIPHeader_IPv6->ucVersionTrafficClass;
                }
                break;
        #endif /* ( ipconfigUSE_IPv6 != 0 ) */

        #if ( ipconfigUSE_IPv4 != 0 )
            case ipIPv4_FRAME_TYPE:
               {
                   size_t uxLength = ( size_t ) pxIPHeader->ucVersionHeaderLength;

                   /* Check if the IP headers are acceptable and if it has our destination.
                    * The lowest four bits of 'ucVersionHeaderLength' indicate the IP-header
                    * length in multiples of 4. */
                   uxHeaderLength = ( size_t ) ( ( uxLength & 0x0FU ) << 2 );

                   if( ( uxHeaderLength > ( pxNetworkBuffer->xDataLength - ipSIZE_OF_ETH_HEADER ) ) ||
                       ( uxHeaderLength < ipSIZE_OF_IPv4_HEADER ) )
                   {
                       eReturn = eReleaseBuffer;
                   }
                   else
                   {
                       ucProtocol = pxIPPacket->xIPHeader.ucProtocol;
                       /* Check if the IP headers are acceptable and if it has our destination. */
                       eReturn = prvAllowIPPacketIPv4( pxIPPacket, pxNetworkBuffer, uxHeaderLength );

                       {
                           /* The IP-header type is copied to a special reserved location a few bytes before the
                            * messages starts.  It might be needed later on when a UDP-payload
                            * buffer is being used. */
                           pxNetworkBuffer->pucEthernetBuffer[ 0 - ( BaseType_t ) ipIP_TYPE_OFFSET ] = pxIPHeader->ucVersionHeaderLength;
                       }
                   }

                   break;
               }
        #endif /* ( ipconfigUSE_IPv4 != 0 ) */

        default:
            eReturn = eReleaseBuffer;
            FreeRTOS_debug_printf( ( "prvProcessIPPacket: Undefined Frame Type \n" ) );
            /* MISRA 16.4 Compliance */
            break;
    }

    /* MISRA Ref 14.3.1 [Configuration dependent invariant] */
    /* More details at: https://github.com/FreeRTOS/FreeRTOS-Plus-TCP/blob/main/MISRA.md#rule-143 */
    /* coverity[misra_c_2012_rule_14_3_violation] */
    /* coverity[cond_const] */
    if( eReturn == eProcessBuffer )
    {
        /* Are there IP-options. */
        /* Case default is never toggled because eReturn is not eProcessBuffer in previous step. */
        switch( pxIPPacket->xEthernetHeader.usFrameType ) /* LCOV_EXCL_BR_LINE */
        {
            #if ( ipconfigUSE_IPv4 != 0 )
                case ipIPv4_FRAME_TYPE:

                    if( uxHeaderLength > ipSIZE_OF_IPv4_HEADER )
                    {
                        /* The size of the IP-header is larger than 20 bytes.
                         * The extra space is used for IP-options. */
                        eReturn = prvCheckIP4HeaderOptions( pxNetworkBuffer );
                    }
                    break;
            #endif /* ( ipconfigUSE_IPv4 != 0 ) */

            #if ( ipconfigUSE_IPv6 != 0 )
                case ipIPv6_FRAME_TYPE:

                    if( xGetExtensionOrder( ucProtocol, 0U ) > 0 )
                    {
                        eReturn = eHandleIPv6ExtensionHeaders( pxNetworkBuffer, pdTRUE );

                        if( eReturn != eReleaseBuffer )
                        {
                            /* Ignore warning for `pxIPHeader_IPv6`. */
                            ucProtocol = pxIPHeader_IPv6->ucNextHeader;
                        }
                    }
                    break;
            #endif /* ( ipconfigUSE_IPv6 != 0 ) */

            /* Case default is never toggled because eReturn is not eProcessBuffer in previous step. */
            default:   /* LCOV_EXCL_LINE */
                /* MISRA 16.4 Compliance */
                break; /* LCOV_EXCL_LINE */
        }

        /* MISRA Ref 14.3.1 [Configuration dependent invariant] */
        /* More details at: https://github.com/FreeRTOS/FreeRTOS-Plus-TCP/blob/main/MISRA.md#rule-143 */
        /* coverity[misra_c_2012_rule_14_3_violation] */
        /* coverity[const] */
        if( eReturn != eReleaseBuffer )
        {
            /* Add the IP and MAC addresses to the ARP table if they are not
             * already there - otherwise refresh the age of the existing
             * entry. */
            if( ucProtocol != ( uint8_t ) ipPROTOCOL_UDP )
            {
                if( xCheckRequiresARPResolution( pxNetworkBuffer ) == pdTRUE )
                {
                    eReturn = eWaitingARPResolution;
                }
                else
                {
                    /* Refresh the ARP cache with the IP/MAC-address of the received
                     * packet.  For UDP packets, this will be done later in
                     * xProcessReceivedUDPPacket(), as soon as it's know that the message
                     * will be handled.  This will prevent the ARP cache getting
                     * overwritten with the IP address of useless broadcast packets. */
                    /* Case default is never toggled because eReturn is not eProcessBuffer in previous step. */
                    switch( pxIPPacket->xEthernetHeader.usFrameType ) /* LCOV_EXCL_BR_LINE */
                    {
                        #if ( ipconfigUSE_IPv6 != 0 )
                            case ipIPv6_FRAME_TYPE:
                                vNDRefreshCacheEntry( &( pxIPPacket->xEthernetHeader.xSourceAddress ), &( pxIPHeader_IPv6->xSourceAddress ), pxNetworkBuffer->pxEndPoint );
                                break;
                        #endif /* ( ipconfigUSE_IPv6 != 0 ) */

                        #if ( ipconfigUSE_IPv4 != 0 )
                            case ipIPv4_FRAME_TYPE:
                                /* Refresh the age of this cache entry since a packet was received. */
                                vARPRefreshCacheEntryAge( &( pxIPPacket->xEthernetHeader.xSourceAddress ), pxIPHeader->ulSourceIPAddress );
                                break;
                        #endif /* ( ipconfigUSE_IPv4 != 0 ) */

                        /* Case default is never toggled because eReturn is not eProcessBuffer in previous step. */
                        default:   /* LCOV_EXCL_LINE */
                            /* MISRA 16.4 Compliance */
                            break; /* LCOV_EXCL_LINE */
                    }
                }
            }

            if( eReturn != eWaitingARPResolution ) /*TODO eReturn != eReleaseBuffer */
            {
                switch( ucProtocol )
                {
                    #if ( ipconfigUSE_IPv4 != 0 )
                        case ipPROTOCOL_ICMP:

                            /* The IP packet contained an ICMP frame.  Don't bother checking
                             * the ICMP checksum, as if it is wrong then the wrong data will
                             * also be returned, and the source of the ping will know something
                             * went wrong because it will not be able to validate what it
                             * receives. */
                            #if ( ipconfigREPLY_TO_INCOMING_PINGS == 1 ) || ( ipconfigSUPPORT_OUTGOING_PINGS == 1 )
                                {
                                    eReturn = ProcessICMPPacket( pxNetworkBuffer );
                                }
                            #endif /* ( ipconfigREPLY_TO_INCOMING_PINGS == 1 ) || ( ipconfigSUPPORT_OUTGOING_PINGS == 1 ) */
                            break;
                    #endif /* ( ipconfigUSE_IPv4 != 0 ) */

                    #if ( ipconfigUSE_IPv6 != 0 )
                        case ipPROTOCOL_ICMP_IPv6:
                            eReturn = prvProcessICMPMessage_IPv6( pxNetworkBuffer );
                            break;
                    #endif /* ( ipconfigUSE_IPv6 != 0 ) */

                    case ipPROTOCOL_UDP:
                        /* The IP packet contained a UDP frame. */

                        eReturn = prvProcessUDPPacket( pxNetworkBuffer );
                        break;

                        #if ipconfigUSE_TCP == 1
                            case ipPROTOCOL_TCP:

                                if( xProcessReceivedTCPPacket( pxNetworkBuffer ) == pdPASS )
                                {
                                    eReturn = eFrameConsumed;
                                }

                                /* Setting this variable will cause xTCPTimerCheck()
                                 * to be called just before the IP-task blocks. */
                                xProcessedTCPMessage++;
                                break;
                        #endif /* if ipconfigUSE_TCP == 1 */
                    default:
                        /* Not a supported frame type. */
                        eReturn = eReleaseBuffer;
                        break;
                }
            }
        }
    }

    return eReturn;
}
