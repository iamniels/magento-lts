<?php
/**
 * Magento
 *
 * NOTICE OF LICENSE
 *
 * This source file is subject to the Open Software License (OSL 3.0)
 * that is bundled with this package in the file LICENSE.txt.
 * It is also available through the world-wide-web at this URL:
 * http://opensource.org/licenses/osl-3.0.php
 * If you did not receive a copy of the license and are unable to
 * obtain it through the world-wide-web, please send an email
 * to license@magento.com so we can send you a copy immediately.
 *
 * DISCLAIMER
 *
 * Do not edit or add to this file if you wish to upgrade Magento to newer
 * versions in the future. If you wish to customize Magento for your
 * needs please refer to http://www.magento.com for more information.
 *
 * @category    Mage
 * @package     Mage_Downloadable
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (http://www.magento.com)
 * @license    http://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

/**
 * Downloadable Products Download Helper
 *
 * @category    Mage
 * @package     Mage_Downloadable
 * @author      Magento Core Team <core@magentocommerce.com>
 */
class Mage_Downloadable_Helper_Download extends Mage_Core_Helper_Abstract
{
    const LINK_TYPE_URL         = 'url';
    const LINK_TYPE_FILE        = 'file';

    const XML_PATH_CONTENT_DISPOSITION  = 'catalog/downloadable/content_disposition';

    /**
     * Type of link
     *
     * @var string
     */
    protected $_linkType        = self::LINK_TYPE_FILE;

    /**
     * Resource file
     *
     * @var string
     */
    protected $_resourceFile    = null;

    /**
     * Resource open handle
     *
     * @var resource
     */
    protected $_handle          = null;

    /**
     * Remote server headers
     *
     * @var array
     */
    protected $_urlHeaders      = array();

    /**
     * MIME Content-type for a file
     *
     * @var string
     */
    protected $_contentType     = 'application/octet-stream';

    /**
     * File name
     *
     * @var string
     */
    protected $_fileName        = 'download';

    /**
     * Return a resolved public address for a remote download host.
     *
     * CVE-2024-34111.
     *
     * @param array $urlProp Parsed URL components
     * @return string
     * @throws Mage_Core_Exception
     */
    protected function _getSafeRemoteHost(array $urlProp)
    {
        if (!isset($urlProp['host']) || $urlProp['host'] === ''
            || isset($urlProp['user']) || isset($urlProp['pass'])) {
            Mage::throwException(Mage::helper('downloadable')->__('Invalid download URL host.'));
        }

        $host = $urlProp['host'];
        if (substr($host, 0, 1) === '[' && substr($host, -1) === ']') {
            $host = substr($host, 1, -1);
        }
        $addresses = array();
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            $addresses[] = $host;
        } elseif (function_exists('dns_get_record')) {
            $recordTypes = 0;
            if (defined('DNS_A')) {
                $recordTypes |= DNS_A;
            }
            if (defined('DNS_AAAA')) {
                $recordTypes |= DNS_AAAA;
            }
            if ($recordTypes) {
                $records = @dns_get_record($host, $recordTypes);
                if (is_array($records)) {
                    foreach ($records as $record) {
                        if (isset($record['ip'])) {
                            $addresses[] = $record['ip'];
                        } elseif (isset($record['ipv6'])) {
                            $addresses[] = $record['ipv6'];
                        }
                    }
                }
            }
        }

        if (!$addresses && function_exists('gethostbynamel')) {
            $resolved = @gethostbynamel($host);
            if (is_array($resolved)) {
                $addresses = $resolved;
            }
        }

        $addresses = array_values(array_unique($addresses));
        if (!$addresses) {
            Mage::throwException(Mage::helper('downloadable')->__('Unable to resolve download URL host.'));
        }

        foreach ($addresses as $address) {
            if (!$this->_isPublicRemoteAddress($address)) {
                Mage::throwException(Mage::helper('downloadable')->__('Download URL host resolves to a restricted address.'));
            }
        }

        // Connect to the validated address rather than resolving the hostname again.
        return $addresses[0];
    }

    /**
     * Check whether an address is globally routable (not local or reserved).
     *
     * CVE-2024-34111.
     *
     * @param string $address
     * @return bool
     */
    protected function _isPublicRemoteAddress($address)
    {
        $packed = @inet_pton($address);
        if ($packed === false) {
            return false;
        }

        if (strlen($packed) === 4) {
            $parts = array_map('intval', explode('.', $address));
            if (count($parts) !== 4) {
                return false;
            }
            $first = $parts[0];
            $second = $parts[1];
            return $first !== 0 && $first !== 10 && $first !== 127
                && $first < 224
                && !($first === 100 && $second >= 64 && $second <= 127)
                && !($first === 169 && $second === 254)
                && !($first === 172 && $second >= 16 && $second <= 31)
                && !($first === 192 && in_array($second, array(0, 2, 88, 168), true))
                && !($first === 198 && in_array($second, array(18, 19, 51), true))
                && !($first === 203 && $second === 0);
        }

        // IPv4-mapped IPv6 addresses must receive the IPv4 restrictions too.
        if (substr($packed, 0, 12) === str_repeat("\0", 10) . "\xff\xff") {
            return $this->_isPublicRemoteAddress(inet_ntop(substr($packed, 12)));
        }

        $bytes = array_values(unpack('C*', $packed));
        $allZero = true;
        foreach ($bytes as $byte) {
            if ($byte !== 0) {
                $allZero = false;
                break;
            }
        }
        return !$allZero
            && !($bytes[15] === 1 && array_sum(array_slice($bytes, 0, 15)) === 0)
            && ($bytes[0] & 0xfe) !== 0xfc
            && !($bytes[0] === 0xfe && ($bytes[1] & 0xc0) === 0x80)
            && $bytes[0] !== 0xff
            && !($bytes[0] === 0x20 && $bytes[1] === 0x01
                && $bytes[2] === 0x0d && $bytes[3] === 0xb8);
    }

    /**
     * Retrieve Resource file handle (socket, file pointer etc)
     *
     * @return resource
     */
    protected function _getHandle()
    {
        if (!$this->_resourceFile) {
            Mage::throwException(Mage::helper('downloadable')->__('Please set resource file and link type.'));
        }

        if (is_null($this->_handle)) {
            if ($this->_linkType == self::LINK_TYPE_URL) {

                /**
                 * Validate URL
                 */
                $urlProp = parse_url($this->_resourceFile);
                // CVE-2024-34111: Restrict remote downloads to validated HTTP(S) destinations.
                $urlScheme = isset($urlProp['scheme']) ? strtolower($urlProp['scheme']) : '';
                if (!in_array($urlScheme, array('http', 'https'), true)) {
                    Mage::throwException(Mage::helper('downloadable')->__('Invalid download URL scheme.'));
                }
                if (!isset($urlProp['host'])) {
                    Mage::throwException(Mage::helper('downloadable')->__('Invalid download URL host.'));
                }
                $port = $urlScheme === 'https' ? 443 : 80;
                // Resolve the destination before opening a socket. Download URLs may be
                // supplied through the catalog API, so do not allow them to target local,
                // private, link-local, or otherwise reserved address space.
                $connectHost = $this->_getSafeRemoteHost($urlProp);
                if (strpos($connectHost, ':') !== false) {
                    $connectHost = '[' . $connectHost . ']';
                }

                if (isset($urlProp['port'])) {
                    $port = (int)$urlProp['port'];
                    if ($port < 1 || $port > 65535) {
                        Mage::throwException(Mage::helper('downloadable')->__('Invalid download URL port.'));
                    }
                }

                $path = '/';
                if (isset($urlProp['path'])) {
                    $path = $urlProp['path'];
                }
                $query = '';
                if (isset($urlProp['query'])) {
                    $query = '?' . $urlProp['query'];
                }

                $errno = 0;
                $errstr = '';
                if ($urlScheme === 'https') {
                    // CVE-2024-34111: Pin the validated address while retaining the original hostname for
                    // SNI and certificate verification.
                    $peerName = trim($urlProp['host'], '[]');
                    $context = stream_context_create(array(
                        'ssl' => array(
                            'peer_name' => $peerName,
                            'SNI_enabled' => true,
                            'SNI_server_name' => $peerName,
                            'verify_peer' => true,
                            'verify_peer_name' => true,
                        ),
                    ));
                    $timeout = (float) ini_get('default_socket_timeout');
                    if ($timeout <= 0) {
                        $timeout = 60;
                    }
                    $this->_handle = @stream_socket_client(
                        'ssl://' . $connectHost . ':' . $port,
                        $errno,
                        $errstr,
                        $timeout,
                        STREAM_CLIENT_CONNECT,
                        $context
                    );
                } else {
                    $this->_handle = @fsockopen($connectHost, $port, $errno, $errstr);
                }

                if ($this->_handle === false) {
                    Mage::throwException(Mage::helper('downloadable')->__('Cannot connect to remote host, error: %s.', $errstr));
                }

                $headers = 'GET ' . $path . $query . ' HTTP/1.0' . "\r\n"
                    . 'Host: ' . $urlProp['host'] . "\r\n"
                    . 'User-Agent: Magento ver/' . Mage::getVersion() . "\r\n"
                    . 'Connection: close' . "\r\n"
                    . "\r\n";
                fwrite($this->_handle, $headers);

                while (!feof($this->_handle)) {
                    $str = fgets($this->_handle, 1024);
                    if ($str == "\r\n") {
                        break;
                    }
                    $match = array();
                    if (preg_match('#^([^:]+): (.*)\s+$#', $str, $match)) {
                        $k = strtolower($match[1]);
                        if ($k == 'set-cookie') {
                            continue;
                        } else {
                            $this->_urlHeaders[$k] = trim($match[2]);
                        }
                    } elseif (preg_match('#^HTTP/[0-9\.]+ (\d+) (.*)\s$#', $str, $match)) {
                        $this->_urlHeaders['code'] = $match[1];
                        $this->_urlHeaders['code-string'] = trim($match[2]);
                    }
                }

                if (!isset($this->_urlHeaders['code']) || $this->_urlHeaders['code'] != 200) {
                    Mage::throwException(Mage::helper('downloadable')->__('An error occurred while getting the requested content. Please contact the store owner.'));
                }
            } elseif ($this->_linkType == self::LINK_TYPE_FILE) {
                $this->_handle = new Varien_Io_File();
                if (!is_file($this->_resourceFile)) {
                    Mage::helper('core/file_storage_database')->saveFileToFilesystem($this->_resourceFile);
                }
                $this->_handle->open(array('path'=>Mage::getBaseDir('var')));
                if (!$this->_handle->fileExists($this->_resourceFile, true)) {
                    Mage::throwException(Mage::helper('downloadable')->__('The file does not exist.'));
                }
                $this->_handle->streamOpen($this->_resourceFile, 'r');
            } else {
                Mage::throwException(Mage::helper('downloadable')->__('Invalid download link type.'));
            }
        }
        return $this->_handle;
    }

    /**
     * Retrieve file size in bytes
     */
    public function getFilesize()
    {
        $handle = $this->_getHandle();
        if ($this->_linkType == self::LINK_TYPE_FILE) {
            return $handle->streamStat('size');
        } elseif ($this->_linkType == self::LINK_TYPE_URL) {
            if (isset($this->_urlHeaders['content-length'])) {
                return $this->_urlHeaders['content-length'];
            }
        }
        return null;
    }

    /**
     * @return array|string
     * @throws Exception
     */
    public function getContentType()
    {
        $handle = $this->_getHandle();
        if ($this->_linkType == self::LINK_TYPE_FILE) {
            if (function_exists('mime_content_type') && ($contentType = mime_content_type($this->_resourceFile))) {
                return $contentType;
            } else {
                return Mage::helper('downloadable/file')->getFileType($this->_resourceFile);
            }
        } elseif ($this->_linkType == self::LINK_TYPE_URL) {
            if (isset($this->_urlHeaders['content-type'])) {
                $contentType = explode('; ', $this->_urlHeaders['content-type']);
                return $contentType[0];
            }
        }
        return $this->_contentType;
    }

    /**
     * @return bool|mixed|string
     * @throws Exception
     */
    public function getFilename()
    {
        $handle = $this->_getHandle();
        if ($this->_linkType == self::LINK_TYPE_FILE) {
            return pathinfo($this->_resourceFile, PATHINFO_BASENAME);
        } elseif ($this->_linkType == self::LINK_TYPE_URL) {
            if (isset($this->_urlHeaders['content-disposition'])) {
                $contentDisposition = explode('; ', $this->_urlHeaders['content-disposition']);
                if (!empty($contentDisposition[1]) && strpos($contentDisposition[1], 'filename=') !== false) {
                    return substr($contentDisposition[1], 9);
                }
            }
            if ($fileName = @pathinfo($this->_resourceFile, PATHINFO_BASENAME)) {
                return $fileName;
            }
        }
        return $this->_fileName;
    }

    /**
     * Set resource file for download
     *
     * @param string $resourceFile
     * @param string $linkType
     * @return $this
     */
    public function setResource($resourceFile, $linkType = self::LINK_TYPE_FILE)
    {
        if (self::LINK_TYPE_FILE == $linkType) {
            //check LFI protection
            /** @var Mage_Core_Helper_Data $helper */
            $helper = Mage::helper('core');
            $helper->checkLfiProtection($resourceFile);
        }

        $this->_resourceFile    = $resourceFile;
        $this->_linkType        = $linkType;

        return $this;
    }

    /**
     * Retrieve Http Request Object
     *
     * @return Mage_Core_Controller_Request_Http
     */
    public function getHttpRequest()
    {
        return Mage::app()->getFrontController()->getRequest();
    }

    /**
     * Retrieve Http Response Object
     *
     * @return Mage_Core_Controller_Response_Http
     */
    public function getHttpResponse()
    {
        return Mage::app()->getFrontController()->getResponse();
    }

    public function output()
    {
        $handle = $this->_getHandle();
        if ($this->_linkType == self::LINK_TYPE_FILE) {
            while ($buffer = $handle->streamRead()) {
                print $buffer;
            }
        } elseif ($this->_linkType == self::LINK_TYPE_URL) {
            while (!feof($handle)) {
                print fgets($handle, 1024);
            }
        }
    }

    /**
     * Use Content-Disposition: attachment
     *
     * @param mixed $store
     * @return bool
     */
    public function getContentDisposition($store = null)
    {
        return Mage::getStoreConfig(self::XML_PATH_CONTENT_DISPOSITION, $store);
    }
}
