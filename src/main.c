/*
 * main.c
 *
 * Main entry point of the compiled CLI application.
 *
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <signal.h>
#include <string.h>
#include <getopt.h>
#include <err.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>

#include <linux/limits.h>

#include "api.h"
#include "pattern.h"
#include "xoroshiro.h"
#include "generator.h"



void __print_usage_info() {
    printf(
        "Usage: nanofuzz {-i|-p pattern|-f pattern-file} [-l count] [-n]\n"
        "\n"
        "Generates fuzzer data from a provided pattern or schema, input through one of\n"
        "  three different methods. For more information about writing patterns for this\n"
        "  tool, see the provided man-page.\n"
        "\n"
        "Options:\n"
        "    -h, --help         Display this help.\n"
        "    -i, --stdin        Read the pattern schema as a string from STDIN.\n"
        "    -p, --pattern      Read the pattern schema from the provided option parameter.\n"
        "    -f, --file         Read the pattern schema from a specified text file.\n"
        "    -l, --limit        Print only 'count' generated lines and stop.\n"
        "    -n, --nocrlf       Do not interpret new-line characters (CR or LF) as part\n"
        "                         of the pattern sequence. When this option is used, the\n"
        "                         character literals '\\r' and '\\n' should be used when a\n"
        "                         literal carriage return or line feed is in the pattern.\n"
        "\n"
        "\n"
    );
    exit( 1 );
}



// Other function declarations.
static void register_signal_handlers();
static void handle_signal( int signal );
static char* read_data_from_file( FILE* fp_file, bool gets_size );
#ifdef DEBUG
void print_hex( const char* p_dump_tag, const char* p_content, size_t len ) {
    printf( "DEBUG: HEX of '%s':\n", p_dump_tag );
    for ( size_t c = 0; c < len; c++ ) {
        if ( c % 8 == 0 )  printf( "    " );
        if ( c % 16 == 0 )  printf( "\n" );
        printf( "%02X ", (unsigned char)*(p_content+c) );
    }
    printf( "\n\n" );
}
#else   /* DEBUG */
void print_hex( const char* p_dump_tag, const char* p_content, size_t len ) {  }
#endif   /* DEBUG */

// Define a flags register and some bit indices.
static uint32_t app_flags = 0x00000000;
#define FLAG_PATTERN_STDIN (1 << 0)
#define FLAG_PATTERN_STRING (1 << 1)
#define FLAG_PATTERN_FILE (1 << 2)
#define FLAG_NO_CRLF (1 << 3)
#define FLAG_COUNT_SET (1 << 4)


// Main.
int main( int argc, char* const argv[] ) {
    // Initial application setup.
    register_signal_handlers();

    // Set up options.
    struct option cli_long_opts[] = {
        { "help",     no_argument,        NULL,  'h' },
        { "stdin",    no_argument,        NULL,  'i' },
        { "pattern",  required_argument,  NULL,  'p' },
        { "file",     required_argument,  NULL,  'f' },
        { "limit",    required_argument,  NULL,  'l' },
        { "nocrlf",   no_argument,        NULL,  'n' },
        { NULL,       0,                  NULL,   0  }
    };

    int cli_opt_idx = 0;
    int cli_opt;

    char* p_pattern_file_path = NULL;
    char* p_pattern_contents = NULL;

    size_t amount_to_generate = 1;

    for ( ; ; ) {
        cli_opt = getopt_long( argc, argv, "hip:f:l:n", cli_long_opts, &cli_opt_idx );
        if ( cli_opt == -1 )  break;
        switch ( cli_opt ) {
            case '?':
            case 'h':
            default :
                __print_usage_info();
                break;

            case 'i':
                if ( (app_flags & FLAG_PATTERN_FILE) || (app_flags & FLAG_PATTERN_STRING) )
                    errx( 1, "The '-i', '-p', or '-f' flags are mutually exclusive. Please use only ONE of them.\n" );

                app_flags |= FLAG_PATTERN_STDIN;
                break;

            case 'p':
                if ( (app_flags & FLAG_PATTERN_FILE) || (app_flags & FLAG_PATTERN_STDIN) )
                    errx( 1, "The '-i', '-p', or '-f' flags are mutually exclusive. Please use only ONE of them.\n" );
                else if ( (app_flags & FLAG_PATTERN_STRING) )
                    errx( 1, "The pattern string (-p) option can only be specified once.\n" );

                app_flags |= FLAG_PATTERN_STRING;

                // Initialize the pattern directly from the option argument.
                if ( strnlen( optarg, FUZZ_MAX_PATTERN_LENGTH ) >= FUZZ_MAX_PATTERN_LENGTH ) {
                    errx( 1, "The given pattern exceeds the maximum parseable pattern length of %lu bytes.\n",
                        (unsigned long)FUZZ_MAX_PATTERN_LENGTH );
                } else if ( strnlen( optarg, 1 ) ) {
                    p_pattern_contents = strndup( optarg, (FUZZ_MAX_PATTERN_LENGTH-1) );
                    p_pattern_contents[strlen(p_pattern_contents)] = '\0';
                } else {
                    errx( 1, "A valid pattern must be supplied with the '-p' flag.\n" );
                }

                break;

            case 'f':
                if ( (app_flags & FLAG_PATTERN_STDIN) || (app_flags & FLAG_PATTERN_STRING) )
                    errx( 1, "The '-i', '-p', or '-f' flags are mutually exclusive. Please use only ONE of them.\n" );
                else if ( (app_flags & FLAG_PATTERN_FILE) || p_pattern_file_path != NULL )
                    errx( 1, "The pattern file (-f) option can only be specified once.\n" );

                app_flags |= FLAG_PATTERN_FILE;

                // Copy the file path from the option argument into the file_path pointer, if not already set.
                if ( strnlen( optarg, (PATH_MAX-1) ) < 1 )
                    errx( 1, "The pattern file (-f) must be a path to a readable text file.\n" );

                p_pattern_file_path = strndup( optarg, (PATH_MAX-1) );
                if ( p_pattern_file_path == NULL )
                    errx( 1, "Failed to understand or copy the '-f' option argument string.\n" );

                break;

            case 'l':
                if ( (app_flags & FLAG_COUNT_SET) )
                    errx( 1, "The count of generated lines can only be specified once.\n" );

                app_flags |= FLAG_COUNT_SET;

                if ( strnlen( optarg, 3 ) == 2 && strncmp( optarg, "-1", 2 ) == 0 ) {
                    amount_to_generate = 0;   //infinite
                } else {
                    for ( const char* x = optarg; (*x); x++ )
                        if ( !isdigit( (int)(*x) ) )
                            errx( 1, "The '-l' option's value must be a positive, base-10 (decimal) integer.\n" );

                    errno = 0;
                    amount_to_generate = (size_t)strtoul( optarg, NULL, 10 );
                    if ( errno ) {
                        perror( "'-l' option" );
                        exit( 1 );
                    }
                }

                break;

            case 'n':
                app_flags |= FLAG_NO_CRLF;
                break;
        }
    }


    // Now double-check options provided through the application's options as needed.
    if ( (app_flags & FLAG_PATTERN_FILE) ) {

        // Open the file and make sure the handle is OK.
        FILE* fp_pattern_file = fopen( p_pattern_file_path, "rb" );
        if ( !fp_pattern_file )  errx( 1, "Unable to open pattern file '%s'.\n", p_pattern_file_path );

        // Get the data from the pattern file.
        p_pattern_contents = read_data_from_file( fp_pattern_file, true );

        // Close the file handle and release pointers as appropriate.
        fclose( fp_pattern_file );
        if ( p_pattern_file_path != NULL )  free( p_pattern_file_path );

    } else if ( (app_flags & FLAG_PATTERN_STDIN) ) {

        // Read the contents of the pattern string from STDIN.
        errno = 0;
        FILE* fp_stdin = freopen( NULL, "rb", stdin );
        if ( !fp_stdin ) {
            perror( "problem reading from STDIN fd" );
            exit( 1 );
        }

        // Attempt to read the data from STDIN.
        p_pattern_contents = read_data_from_file( fp_stdin, false );

        // Close the 'reopened' STDIN stream.
        fclose( fp_stdin );
    }

    // Check that a pattern actually exists to parse.
    if ( NULL == p_pattern_contents || !strnlen( p_pattern_contents, 1 ) )
        errx( 1, "A pattern to parse was not found. Please check the provided options and try again.\n" );

    // Create a new error context to read problems from the pattern string, if any.
    fuzz_error_t* p_err_ctx = Error__new();

    // Parse it and generate a pattern factory in the background.
    fuzz_factory_t* p_pattern_factory = PatternFactory__new( p_pattern_contents, p_err_ctx );
    if ( NULL == p_pattern_factory ) {
        Error__print( p_err_ctx, stderr );
        exit( 1 );
    } else {
        // TEST CODE //
        printf( "Data size: %lu\n", PatternFactory__get_data_size( p_pattern_factory ) );
        print_hex(
            "factory node_seq",
            PatternFactory__get_data( p_pattern_factory ),
            PatternFactory__get_data_size( p_pattern_factory )
        );

        // Explain the factory.
        PatternFactory__explain( stdout, p_pattern_factory );
        ///////////////
    }

    // TEST CODE
    printf( "Generating '%lu' values. OK\n", amount_to_generate );
    fuzz_gen_ctx_t* p_genctx = Generator__new_context( p_pattern_factory, normal );

    for ( size_t t = 0; t < amount_to_generate; t++ )
        printf(  "FUZZ: %s\n", Generator__get_next( p_genctx )  );

/*    printf( "Input content is %lu bytes long.\n", (unsigned long)strlen(p_pattern_contents) );
    printf( "Read bytes:\n" );
    print_hex( "Pattern Contents", p_pattern_contents, strlen( p_pattern_contents ) );
    printf( "\n\n" );
    printf( "%lu\n", time(NULL) );
    xoroshiro256p_state_t* rand_state = xoroshiro__new( time(NULL) );
    for( int i = 0; i < 10; i++ )
        printf( "%lu\n", xoroshiro__get_next( rand_state ) );
    for( int i = 0; i < 10; i++ )
        printf( "%d\n", xoroshiro__get_byte( rand_state ) );
    for( int i = 0; i < 10; i++ )
        printf( "%d\n", xoroshiro__get_bounded_byte( rand_state, 5, 15 ) );*/
    // -- END TESTS


    // Initialize the pattern parser. A lot going on 'behind the scenes' here.
    // TODO: initialize

    // Free unnecessary allocations.
//    PatternFactory__delete( p_pattern_factory );
    free( p_pattern_contents );
}



static void register_signal_handlers() {
    static struct sigaction sa;
    memset( &sa, 0, sizeof(struct sigaction) );
    sa.sa_handler = handle_signal;
    sigaction( SIGINT,  &sa, NULL );
    sigaction( SIGTERM, &sa, NULL );
    sigaction( SIGHUP,  &sa, NULL );
    return;
}


static void handle_signal( int signal ) {
    fprintf( stderr, "Received signal '%d'. Goodbye.\n", signal );
    exit( 0 );
}


static char* read_data_from_file( FILE* fp_file, bool gets_size ) {
        // Ensure the pattern file or STDIN is valid, and a string with 1 or more chars is read from it.
        static char buffer[32] = {0};
        size_t bytes = 0, read_count = 0, file_size = 0;
        char* p_pattern_data;

        // Get the file size.
        if ( gets_size ) {
            errno = 0;
            fseek( fp_file, 0L, SEEK_END );
            if ( errno ) {
                perror( "fseek end: unseekable file" );
                exit( 1 );
            }
            errno = 0;
            file_size = ftell( fp_file );
            fseek( fp_file, 0L, SEEK_SET );
            if ( errno ) {
                perror( "fseek set: unseekable file" );
                exit( 1 );
            }
        } else  file_size = (FUZZ_MAX_PATTERN_LENGTH-1);

        // Make sure it doesn't exceed the maximum parseable pattern length.
        if ( file_size >= FUZZ_MAX_PATTERN_LENGTH )
            errx( 1, "The given pattern exceeds the maximum parseable pattern size of %lu bytes.\n",
                (unsigned long)FUZZ_MAX_PATTERN_LENGTH );

        // Allocate the buffer in the heap to store the file's contents.
        char* p_read = (char*)calloc( 1, (file_size+1) );

        while ( (bytes = fread( buffer, sizeof(unsigned char), sizeof(buffer), fp_file )) ) {
            if ( (read_count+bytes) > file_size )
                errx( 1, "The pattern exceeded the expected file size of %lu bytes.\n", file_size );

            if ( strnlen( buffer, sizeof(buffer) ) )
                strcat( p_read, buffer );

            memset( buffer, 0, sizeof(buffer) );

            // Keep counting.
            read_count += bytes;
        }

        // Now assign the read contents to the pattern_contents location.
/*        char* p_final = (char*)calloc( read_count+1, sizeof(char) );
        memcpy( p_final, p_read, read_count );
        p_final[read_count] = '\0';*/
        p_pattern_data = strndup(  p_read, strnlen( p_read, FUZZ_MAX_PATTERN_LENGTH-1 )  );

        if ( p_read != NULL )  free( p_read );

        // One last check to make sure the pattern is filled.
        if ( !strnlen( p_pattern_data, 2 ) )
            errx( 1, "Unable to discern a pattern. Was one properly provided?\n" );

        return p_pattern_data;
}
