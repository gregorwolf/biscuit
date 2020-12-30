CLASS zcl_biscuit DEFINITION
  PUBLIC
  FINAL
  CREATE PRIVATE .

  PUBLIC SECTION.

    DATA error TYPE sy-subrc .

    CLASS-METHODS get_biscuit
      IMPORTING
        !ssf_app       TYPE ssfappl DEFAULT 'SSO2'
        !sysid         TYPE sysysid DEFAULT sy-sysid
        !client        TYPE mandt DEFAULT sy-mandt
      RETURNING
        VALUE(biscuit) TYPE REF TO zcl_biscuit .
    METHODS get_ticket
      IMPORTING
        !user         TYPE xubname
        !hours        TYPE int4 DEFAULT 8
      RETURNING
        VALUE(ticket) TYPE string .
  PROTECTED SECTION.
  PRIVATE SECTION.

    DATA ssf_app TYPE ssfappl .
    DATA sysid TYPE sysysid .
    DATA client TYPE mandt .
    DATA user TYPE xubname .
    DATA validity TYPE int4 .
    DATA bdata TYPE xstring .
    DATA signature TYPE xstring .

    METHODS create_data .
    METHODS sign_data .
    METHODS split_data
      RETURNING
        VALUE(table) TYPE rmps_ssfbin .
    METHODS constructor
      IMPORTING
        !ssf_app TYPE ssfappl
        !sysid   TYPE sysysid
        !client  TYPE mandt .
    METHODS append_signature .
ENDCLASS.



CLASS ZCL_BISCUIT IMPLEMENTATION.


  METHOD append_signature.
    FIELD-SYMBOLS: <len> TYPE x.
    DATA: len    TYPE i,
          len2   TYPE int2,
          sign_h TYPE xstring VALUE 'FF'.

* Append prefix to signature
    len = xstrlen( me->signature ).
    len2 = len.
    ASSIGN len2 TO <len> CASTING.
    CONCATENATE sign_h <len> me->signature(len)
      INTO me->signature IN BYTE MODE.

  ENDMETHOD.


  METHOD constructor.
    me->ssf_app = ssf_app.
    me->sysid = sysid.
    me->client = client.
  ENDMETHOD.


  METHOD create_data.
    FIELD-SYMBOLS: <uname>  TYPE x,
                   <client> TYPE x,
                   <sysid>  TYPE x,
                   <cdate>  TYPE x,
                   <val>    TYPE x.

* Field headers
    DATA: version  TYPE x VALUE '02',
          cp       TYPE cpcodepage, "codepage
          cp_x     TYPE xstring,
          user_h   TYPE xstring VALUE '010018', "username header
          client_h TYPE xstring VALUE '020006', "client header
          system_h TYPE xstring VALUE '030010', "system ID
          date_h   TYPE xstring VALUE '040018', "creation date & time
          vhou_h   TYPE xstring VALUE '050004', "validity (hours)
          conv     TYPE REF TO cl_abap_conv_out_ce.

    DATA: cr_date TYPE c LENGTH 12,
          ts      TYPE timestamp.

    CLEAR me->bdata.

* Creation date & time (without secs)
    GET TIME STAMP FIELD ts.
    DIVIDE ts BY 100.
    WRITE ts TO cr_date.

    ASSIGN me->user TO <uname> CASTING.
    ASSIGN me->client TO <client> CASTING.
    ASSIGN me->sysid TO <sysid> CASTING.
    ASSIGN cr_date TO <cdate> CASTING.
    ASSIGN me->validity TO <val> CASTING.

* Determine system codepage
    CALL FUNCTION 'SYSTEM_CODEPAGE'
      IMPORTING
        current_dynamic_codepage = cp.
    conv = cl_abap_conv_out_ce=>create( encoding = 'UTF-8' endian = 'B' ).
    conv->write( data = cp ).
    cp_x = conv->get_buffer( ).

    CONCATENATE
      version cp_x
      user_h <uname>
      client_h <client>
      system_h <sysid>
      date_h <cdate>
      vhou_h <val>
      INTO bdata IN BYTE MODE.

  ENDMETHOD.


  METHOD get_biscuit.
* XXX
* Add authorization check here
* to protect this class

    CREATE OBJECT biscuit
      EXPORTING
        ssf_app = ssf_app
        sysid   = sysid
        client  = client.
  ENDMETHOD.


  METHOD get_ticket.
    DATA stream TYPE xstring.

    CLEAR me->error.
    me->user = user.
    me->validity = hours.

    me->create_data( ).
    me->sign_data( ).
    CHECK me->error IS INITIAL.

* Convert to base64
    CONCATENATE me->bdata me->signature
      INTO stream IN BYTE MODE.

    CALL FUNCTION 'SSFC_BASE64_ENCODE'
      EXPORTING
        bindata                  = stream
      IMPORTING
        b64data                  = ticket
      EXCEPTIONS
        ssf_krn_error            = 1
        ssf_krn_noop             = 2
        ssf_krn_nomemory         = 3
        ssf_krn_opinv            = 4
        ssf_krn_input_data_error = 5
        ssf_krn_invalid_par      = 6
        ssf_krn_invalid_parlen   = 7
        OTHERS                   = 8.

    IF sy-subrc <> 0.
      me->error = sy-subrc.
    ENDIF.

  ENDMETHOD.


  METHOD sign_data.

    DATA: len     TYPE i,
          out_len TYPE i,
          input   TYPE STANDARD TABLE OF ssfbin,
          output  TYPE TABLE OF ssfbin,
          line    TYPE ssfbin.

    input = me->split_data( ).

* Sign ticket
    len = xstrlen( me->bdata ).
    CALL FUNCTION 'SSF_KRN_SIGN_BY_AS'
      EXPORTING
        ssfapplication               = me->ssf_app
        ostr_input_data_l            = len
      IMPORTING
        ostr_signed_data_l           = out_len
      TABLES
        ostr_input_data              = input
        ostr_signed_data             = output
      EXCEPTIONS
        ssf_krn_error                = 1
        ssf_krn_noop                 = 2
        ssf_krn_nomemory             = 3
        ssf_krn_opinv                = 4
        ssf_krn_nossflib             = 5
        ssf_krn_input_data_error     = 6
        ssf_krn_invalid_par          = 7
        ssf_krn_invalid_parlen       = 8
        ssf_fb_input_parameter_error = 9
        OTHERS                       = 10.

    IF sy-subrc <> 0.
      me->error = sy-subrc.
      RETURN.
    ENDIF.

* Add signature to cookie
    CLEAR me->signature.
    LOOP AT output INTO line.
      IF out_len GT 255.
        CONCATENATE me->signature line-bindata
          INTO me->signature IN BYTE MODE.
        SUBTRACT 255 FROM out_len.
      ELSE.
        CONCATENATE me->signature line-bindata(out_len)
          INTO me->signature IN BYTE MODE.
      ENDIF.
    ENDLOOP.

    me->append_signature( ).

  ENDMETHOD.


  METHOD split_data.

    DATA: stream    TYPE xstring,
          len       TYPE i,
          len_loops TYPE i,
          len_rem   TYPE i,
          line      TYPE ssfbin.

    CHECK me->bdata IS NOT INITIAL.
    stream = me->bdata.

* Split data into table
    len = xstrlen( stream ).
    len_loops = len DIV 255.
    len_rem = len MOD 255.

    DO len_loops TIMES.
      line-bindata = stream(255).
      APPEND line TO table.
      SHIFT stream BY 255 PLACES IN BYTE MODE.
    ENDDO.
    IF len_rem > 0.
      line-bindata = stream.
      APPEND line TO table.
    ENDIF.

  ENDMETHOD.
ENDCLASS.
