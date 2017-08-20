



function drawAddresses(addresses) {
    console.log(addresses);

    // Clear list first
    $('#walletlist').empty();

    // Loop all wallets, and present them
    var addressIndex = 0;
    $.each(addresses, function() {

        $('#walletlist').append(
            '<div class="event"><div class="content"><div class="summary"><div class="ui horizontal label" style="background-color:#d5a500;">'
            + addressIndex
            + '</div><b style="font-size:1.4em">'
            + this[3] +
            '</b><br><a onclick="showAddress('+ addressIndex +')">'
            + this[0] +
            '</a></div></div></div><div class="ui divider"></div>'
        );

        // Increment address index id
        addressIndex += 1;
    });

    // Remove dimmer
    $('.dimmer').hide();
}


function getAddresses() {
    $('.dimmer').show();

    $('#show-wallet').hide();
    $('#show-all-wallets').show();

    $.ajax({
        url: 'http://localhost:8888/webwallet-addresses',
        dataType: 'json',
        type: "GET",
        success: function(data) {
            drawAddresses(data);
        },
        error: function(data) {
            drawAddresses(data);
        }
    });
}

function createNewAddress() {
    $('.dimmer').show();
    $.ajax({
        url: 'http://localhost:8888/webwallet-create-new-address',
        dataType: 'json',
        type: "GET",
        success: function(data) {
            getAddresses();
        },
        error: function(data) {
           getAddresses();
        }
    });
}


function drawAddress(addresses, showAddressId) {
    console.log(addresses);

    // Clear list first
    $('#walletdetail').empty();

    // Loop all wallets, and present them
    var addressIndex = 0;
    $.each(addresses, function() {

        if(addressIndex == showAddressId) {
            currentDetailAddress = showAddressId;

            $('#walletdetail').append(
                '<div class="event"><div class="content"><div class="summary"><div class="ui horizontal label" style="background-color:#d5a500;">'
                + addressIndex
                + '</div><b style="font-size:1.4em">'
                + this[3] + ' - Type: ' + this[2] + 
                '</b><br><a>'
                + this[0] +
                '</a><br />'+this[4]+'<br />'+this[5]+'</div></div></div><div class="ui divider"></div>'
            );
        }

        // Increment address index id
        addressIndex += 1;
    });

    // Remove dimmer
    $('.dimmer').hide();
}


function showAddress(addressIndex) {
    $('.dimmer').show();

    // Clear to and amount onload
    $('#to').val("");
    $('#amount').val("");

    // Change view
    $('#show-all-wallets').hide();
    $('#show-wallet').show();
    
    // Get addresses then draw
    $.ajax({
        url: 'http://localhost:8888/webwallet-addresses',
        dataType: 'json',
        type: "GET",
        success: function(data) {
            drawAddress(data, addressIndex);
        },
        error: function(data) {
            drawAddress(data, addressIndex);
        }
    });
}



function drawTxnResult(txnResult) {

    // Refresh wallet page to update values
    showAddress(currentDetailAddress);

    // Show modal with results
    if(txnResult.status == "fail") {
        $('#domModalTitle').text('Transaction Failed!');
        $('#domModalBody').html('<b>Error: </b>'+txnResult.message);

        $('#domModal').modal('show');
    } else {
        $('#domModalTitle').text('Transaction Successful');
        $('#domModalBody').html('<b>TXN Hash: </b><a href="http://qrlexplorer.info/search.html#'+txnResult.txnhash+'" target="_blank">'+txnResult.txnhash+'</a><br />'+
                                '<b>From: </b>' + txnResult.from+'<br />'+
                                '<b>To: </b>' + txnResult.to+'<br />'+
                                '<b>Amount: </b>' + txnResult.amount+' Qaunta<br />'
                                );

        $('#domModal').modal('show');
    }

    // Hide loading pane
    $('.dimmer').hide();
}


function sendQuanta() {

    $('.dimmer').show();

    var from = currentDetailAddress;
    var to = $('#to').val();
    var amount = $('#amount').val();

    console.log("Send from index "+from+", to: "+ to + ", amount:"+amount)

    $.ajax({
        url: 'http://localhost:8888/webwallet-send',
        dataType: 'json',
        contentType: 'application/json',
        type: "POST",
        data: JSON.stringify( { "from": from, "to": to, "amount": amount } ),
        processData: false,
        success: function(data) {
            drawTxnResult(data);            
        },
        error: function(data) {
            drawTxnResult(data);
        }
    });
}



// Show addresses on ready
$( document ).ready(function() {
    // Current detail wallet address
    var currentDetailAddress = 0;

    // Hide the detail pane
    $('#show-wallet').hide();

    // Rendor addresses to screen.
    getAddresses();
});



