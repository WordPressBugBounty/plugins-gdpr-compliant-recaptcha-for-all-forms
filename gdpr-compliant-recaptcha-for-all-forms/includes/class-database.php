<?php 

namespace VENDOR\RECAPTCHA_GDPR_COMPLIANT;

use \mysqli;

defined( 'ABSPATH' ) or die( 'Are you ok?' );

/**
 * Class Database: This class is intended to be used as superglobal for the database connection. It is implmenting many methods that are available from $wpdb using mysqli. If mysqli is not available, $wpdb shall be used instead.
 * 
 */
class GDPRDB {
    private $mysqli;
    private $wpdb_available;
    private $mysqli_available;
    private $wpdb;
    private $insert_id;
    public $prefix;

    public function __construct() {
        // Check if mysqli extension is available
        //$this->mysqli_available = false;
        $this->mysqli_available = extension_loaded( 'mysqli' );
        if ( $this->mysqli_available ) {
            $this->mysqli = new mysqli( DB_HOST, DB_USER, DB_PASSWORD, DB_NAME );
            $this->prefix = $GLOBALS['table_prefix'];
            if ($this->mysqli->connect_errno) {
                die( "Connection to MySQL database failed: " . $this->mysqli->connect_error );
            }
        } else {
            global $wpdb;
            $this->wpdb = $wpdb;
            $this->prefix = $wpdb->prefix;
            $this->wpdb_available = class_exists( 'wpdb' );
            if ( ! $this->wpdb_available ) {
                die( "Neither mysqli extension nor \$wpdb is available." );
            }
        }
        $this->measure_runtimes();
    }

    public function measure_runtimes(){
        // Anzahl der Schleifendurchläufe
        $num_iterations = 1000;
        
        // WordPress Standarddatenbankobjekt
        global $wpdb;

        // mysqli Verbindung
        $mysqli = new mysqli(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME);

        // Laufzeiten für wpdb und mysqli initialisieren
        $wpdb_runtimes = [];
        $mysqli_runtimes = [];

        // Schleife für die Wiederholung der Abfragen
        for ($i = 0; $i < $num_iterations; $i++) {
            // Abfrage 1: wpdb
            $start_time_wpdb = microtime(true);

            // Hier deine wpdb-Abfrage einfügen
            $results_wpdb = $wpdb->get_results(
                $wpdb->prepare("SELECT * FROM whistle_recaptcha_gdpr_message_rgm rgm WHERE rgm_id = %d", $i)
            );

            $end_time_wpdb = microtime(true);
            $wpdb_runtime = $end_time_wpdb - $start_time_wpdb;
            $wpdb_runtimes[] = $wpdb_runtime;

            // Abfrage 2: mysqli
            $start_time_mysqli = microtime(true);

            // Hier deine mysqli-Abfrage einfügen
            $stmt = $mysqli->prepare("SELECT * FROM whistle_recaptcha_gdpr_message_rgm rgm WHERE rgm_id = ?");
            $stmt->bind_param("i", $i);
            $stmt->execute();
            $result_mysqli = $stmt->get_result();
            $stmt->close();

            $end_time_mysqli = microtime(true);
            $mysqli_runtime = $end_time_mysqli - $start_time_mysqli;
            $mysqli_runtimes[] = $mysqli_runtime;
        }

        $wpdb_gesamt = array_sum($wpdb_runtimes);
        $mysqli_gesamt = array_sum($mysqli_runtimes);

        $wpdb_schnitt = array_sum($wpdb_runtimes) / count($wpdb_runtimes);
        $mysqli_schnitt = array_sum($mysqli_runtimes) / count($mysqli_runtimes);

        $rel_abw_gesamt = ( $mysqli_gesamt - $wpdb_gesamt  ) / $wpdb_gesamt;
        $rel_abw_schnitt = ( $mysqli_schnitt - $wpdb_schnitt  ) / $wpdb_schnitt;

        // Ergebnisse ausgeben
        error_log("MSQLI weicht um $rel_abw_gesamt Prozent von WPDB ab");

        error_log("WPDB - $num_iterations Wiederholungen: " . array_sum($wpdb_runtimes) . " Sekunden insgesamt " . array_sum($wpdb_runtimes) / count($wpdb_runtimes) . " Sekunden Durchschnitt");
        error_log("MYSQLI - $num_iterations Wiederholungen: " . array_sum($mysqli_runtimes) . " Sekunden insgesamt " . array_sum($mysqli_runtimes) / count($mysqli_runtimes) . " Sekunden Durchschnitt");

        // Verbindung schließen
        $mysqli->close();
    }

    public function query( $sql ) {
        if ( $this->mysqli_available ) {
            if ( is_object( $sql )/*instanceof mysqli_stmt*/ ) {
                // If $sql is already a prepared mysqli_stmt, execute it
                $sql->execute();
                $result = $sql->get_result();
                //$sql->close();
                return $result;
            } else {
                // If $sql is a SQL string, prepare and execute it
                $stmt = $this->prepare( $sql );
                if ($stmt === false) {
                    die("Query preparation failed: " . $this->mysqli->error);
                }
                $stmt->execute();
                $result = $stmt->get_result();
                //$stmt->close();
                return $result;
            }
        } elseif( $this->wpdb_available ) {
            return $this->wpdb->query( $sql );
        } else {
            die( "Neither mysqli extension nor \$wpdb is available." );
        }
    }

    public function fetch_array( $result ) {
        if ( $this->mysqli_available ) {
            return $result->fetch_array();
        } elseif( $this->wpdb_available ) {
            return $this->wpdb->fetch_array( $result );
        } else {
            die( "Neither mysqli extension nor \$wpdb is available." );
        }
    }

    public function convert_sql_for_mysqli($sql) {
        // Replace %i, %d, %s placeholders with ?
        $sql = str_replace(array('%i', '%d', '%s'), '?', $sql);
        return $sql;
    }

    public function extract_formats_from_sql($sql) {
        // Define regular expression to match placeholders
        $pattern = '/%[a-zA-Z]/';

        // Extract placeholders from the SQL string
        preg_match_all($pattern, $sql, $matches);
        $placeholders = $matches[0];

        // Determine formats based on placeholder types
        $formats = '';
        foreach ($placeholders as $placeholder) {
            switch ($placeholder) {
                case '%i':
                    $formats .= 'i'; // integer
                    break;
                case '%d':
                    $formats .= 'd'; // double
                    break;
                case '%s':
                    $formats .= 's'; // string
                    break;
                default:
                    $formats .= 's'; // default to string
                    break;
            }
        }

        return $formats;
    }

    public function prepare( $sql, ...$args ) {
        // Check if $args is an array containing all arguments
        if ( count( $args ) === 1 && is_array( $args[ 0 ] ) ) {
            $args = $args[ 0 ];
        }
        if ( $this->mysqli_available ) {
            // If $args is not empty, prepare and bind parameters
            if ( ! empty( $args ) ) {
                $types = $this->extract_formats_from_sql( $sql );
                $sql = $this->convert_sql_for_mysqli( $sql );
                $stmt = $this->mysqli->prepare( $sql );
                if ( $stmt === false ) {
                    die( "Query preparation failed: " . $this->mysqli->error );
                }

                // Create the array of bind parameters
                $bindParams = array();
                foreach ( $args as &$arg ) {
                    $bindParams[] = &$arg;
                }
                
                //Prepend the types to the parameters array
                array_unshift( $bindParams, $types );

                // Bind parameters
                call_user_func_array( array( $stmt, 'bind_param' ), $bindParams );

                return $stmt;
            } else {
                // If $args is empty, return the prepared SQL string
                return $sql;
            }

        } elseif( $this->wpdb_available ) {
            return $this->wpdb->prepare( $sql, $args );
        } else {
            die( "Neither mysqli extension nor \$wpdb is available." );
        }
    }

    public function get_var( $sql ) {
        if ( $this->mysqli_available ) {
            $result = $this->query( $sql );
            if ($result) {
                $row = $result->fetch_array( MYSQLI_NUM );
                if ( $row ) {
                    return $row[ 0 ];
                }
            }
            return null;
        } elseif( $this->wpdb_available ) {
            return $this->wpdb->get_var( $sql );
        } else {
            die( "Neither mysqli extension nor \$wpdb is available." );
        }
    }

    public function get_col( $sql, $col_offset = 0 ) {
        if ( $this->mysqli_available ) {
            $col = array();
            $result = $this->query( $sql );
            if ($result) {
                while ( $row = $result->fetch_array( MYSQLI_NUM ) ) {
                    $col[] = $row[ $col_offset ];
                }
            }
            return $col;
        } elseif( $this->wpdb_available ) {
            return $this->wpdb->get_col( $sql, $col_offset );
        } else {
            die( "Neither mysqli extension nor \$wpdb is available." );
        }
    }

    public function execute( $sql, $params = null ) {
        if ( $this->mysqli_available ) {
            $stmt = $this->prepare( $sql );
            if ($stmt) {
                if ($params) {
                    $bindParams = array();
                    foreach ( $params as &$param ) {
                        $bindParams[] = &$param;
                    }
                    call_user_func_array( array( $stmt, 'bind_param' ), $bindParams );
                }
                $stmt->execute();
                $result = $stmt->affected_rows;
                $stmt->close();
                return $result;
            } else {
                return false;
            }
        } elseif( $this->wpdb_available ) {
            if ($params) {
                return $this->wpdb->query( $wpdb->prepare( $sql, $params ) );
            } else {
                return $this->wpdb->query( $sql );
            }
        } else {
            die( "Neither mysqli extension nor \$wpdb is available." );
        }
    }

    public function get_results( $sql, $output = 'OBJECT' ) {
        if ( $this->mysqli ) {
            $result = $this->query( $sql );
            if ( $result === false ) {
                die( "Query execution failed: " . $this->mysqli->error );
            }
            $results = array();
            while ( $row = $result->fetch_assoc() ) {
                if ( $output === 'OBJECT' ) {
                    $results[] = ( object )$row;
                } else {
                    $results[] = $row;
                }
            }
            $result->free();
            return $results;
        } elseif ( $this->wpdb_available ) {
            return $this->wpdb->get_results( $sql, $output );
        } else {
            die( "Neither mysqli extension nor \$wpdb is available." );
        }
    }

    public function insert( $table, $data, $format = null ) {
        if ( $this->mysqli_available ) {
            $columns = implode( ', ', array_keys( $data ) );
            $placeholders = array();
            $values = array();
    
            foreach ( $data as $key => $value ) {
                if ( $value === null ) {
                    $placeholders[] = 'NULL';
                } else {
                    $placeholders[] = '?';
                    $values[] = $value;
                }
            }
            $placeholders = implode( ', ', $placeholders );
            $sql = "INSERT INTO $table ($columns) VALUES ($placeholders)";
    
            // Prepare format strings
            if ( is_string( $format ) ) {
                $format = array_fill( 0, count( $data ), $format );
            }
    
            // Check if number of parameters matches number of values
            if ( $format !== null && count( $values ) !== count( $format ) ) {
                die( "Error: Number of format parameters does not match the number of data values." );
            }
    
            // Merge format arrays if needed
            if ( $format === null ) {
                $format = array();
            }
    
            // Bind parameters
            $bindParams = array();
            foreach ( $values as &$value ) {
                if ( $value === null ) {
                    $bindParams[] = null;
                } else {
                    $bindParams[] = &$value;
                }
            }
    
            // Construct types string for parameter binding
            $types = ( $format !== null ) ? implode( '', $format ) : str_repeat( 's', count( $values ) );
            array_unshift($bindParams, $types);
    
            // Execute the prepared statement
            $stmt = $this->prepare( $sql );
            if ( $stmt ) {
                call_user_func_array( array( $stmt, 'bind_param' ), $bindParams );
                $stmt->execute();
                $this->insert_id = $stmt->insert_id;
                $result = $stmt->affected_rows;
                $stmt->close();
                return $result;
            } else {
                return false;
            }
        } elseif( $this->wpdb_available ) {
            $inserted = $this->wpdb->insert( $table, $data, $format );
            $this->insert_id = $this->wpdb->insert_id;
            return $inserted;
        } else {
            die( "Neither mysqli extension nor \$wpdb is available." );
        }
    }

    public function update( $table, $data, $where, $format = null, $where_format = null ) {
        if ( $this->mysqli_available ) {
            $setClauses = array();
            $setValues = array();
            foreach ( $data as $key => $value ) {
                if ( $value === null ) {
                    $setClauses[] = "$key = NULL";
                } else {
                    $setClauses[] = "$key = ?";
                    $setValues[] = $value;
                }
            }
            $setClause = implode( ', ', $setClauses );
            
            $whereClauses = array();
            $whereValues = array();
            foreach ( $where as $key => $value ) {
                if ( $value === null ) {
                    $whereClauses[] = "$key IS NULL";
                } else {
                    $whereClauses[] = "$key = ?";
                    $whereValues[] = $value;
                }
            }
            $whereClause = implode( ' AND ', $whereClauses );
            
            $sql = "UPDATE $table SET $setClause WHERE $whereClause";
    
            // Prepare format strings
            if ( is_string( $format ) ) {
                $format = array_fill( 0, count( $data ), $format );
            }
            if ( is_string( $where_format ) ) {
                $where_format = array_fill( 0, count( $where ), $where_format );
            }
    
            // Check if number of parameters matches number of values
            if ( $format !== null && count( $setValues ) !== count( $format ) ) {
                die( "Error: Number of format parameters does not match the number of data values." );
            }
            if ( $where_format !== null && count( $whereValues ) !== count( $where_format ) ) {
                die( "Error: Number of where_format parameters does not match the number of where values." );
            }
    
            // Merge format arrays if needed
            if ( $format === null ) {
                $format = array();
            }
            if ( $where_format === null ) {
                $where_format = array();
            }
    
            $params = array_merge( $setValues, $whereValues );
    
            return $this->execute( $sql, $params );
        } elseif( $this->wpdb_available ) {
            return $this->wpdb->update( $table, $data, $where, $format, $where_format );
        } else {
            die( "Neither mysqli extension nor \$wpdb is available." );
        }
    }

}

?>