// Current detail wallet address
var currentDetailAddress = 0;

// Manage view state
// 0 = list addresses
// 1 = show single address
// 2 = show node stats
var viewState = 0;

// Init Transactions table
var TransT = $("#TransT").DataTable();

// Draw a row in transactions table
function drawTransRow(a, b, c, d, e, f, g, h) {
    var x = moment.unix(a);
    var z = "";

    if (h == e) {
        z = '<div style=\"text-align: center\"><i class=\"sign out icon\"></i></div>';
    } else {
        z = '<div style=\"text-align: center\"><i class=\"sign in icon\"></i></td></div>';
    }

    var t  = moment(x).format("HH:mm D MMM YYYY");

    //var TransT = $("#TransT").DataTable();
    TransT.row.add([c, d, t, e, z, f, b, g, c, e, f]);
}

// Draws all addresses in wallet file to page.
function drawAddresses(addresses) {
    console.log(addresses);

    viewState = 0;

    // Clear list first
    $('#walletlist').empty();

    // Loop all wallets, and present them
    var addressIndex = 0;
    $.each(addresses, function() {

        var thisAddress = this[0];
        var thisBalance = this[3];

        $('#walletlist').append(
            '<div class="event"><div class="content"><div class="summary"><div class="ui horizontal label" style="background-color:#d5a500;">'
            + addressIndex
            + '</div><b style="font-size:1.4em"><a onclick="showAddress('+ addressIndex +')">'
            + thisAddress +
            '</a></b><br>'
            + thisBalance +
            '</div></div></div><div class="ui divider"></div>'
        );

        // Increment address index id
        addressIndex += 1;
    });

    // Remove dimmer
    $('.dimmer').hide();
}


// Gets detail about the running node
function getNodeInfo(hideDimmer = false) {

    viewState = 2;

    // Dimmer does not show for auto refreshes.
    if(hideDimmer == false) {
        $('.dimmer').show();
    }

    $('#show-wallet').hide();
    $('#show-all-wallets').hide();
    $('#show-node-stats').show();


    /*
    {
      "status": "ok",
      "unmined": 14009974.73883562,
      "network": "qrl testnet",
      "block_reward": 0.84203832,
      "emission": 6990025.26116438,
      "stake_validators": 5,
      "epoch": 0,
      "block_time": 50110414.432299145,
      "version": "alpha/0.27a",
      "staked_percentage_emission": 70.82,
      "blockheight": 30,
      "nodes": 6,
      "block_time_variance": 1503311097.9484582,
      "network_uptime": 8594.410389661789
    }
    */
    $.ajax({
        url: 'http://localhost:8080/api/stats',
        dataType: 'json',
        type: "GET",
        success: function(data) {
            $('.dimmer').hide();


            $('#network').text(':' + data.network);
            var x = moment.duration(data.network_uptime,'seconds').format("d[d] h[h] mm[min]");
            $('#uptime').text(x);
            $('#nodes').text(data.nodes);
            var x = moment.duration(data.block_time_variance,'seconds');
            x = Math.round(x/10)/100;
            $('#variance').text(x + 's');
            var x = moment.duration(data.block_time,'seconds').format("s[s]");
            $('#blocktime').text(x);
            $('#blockheight').text(data.blockheight);
            $('#validators').text(data.stake_validators);
            $('#PCemission').text(data.staked_percentage_emission + '%');
            $('#epoch').text(data.epoch);
            var x = data.emission;
            x = (Math.round(x * 10000)) / 10000;
            $('#emission').text(x);
            var x = data.unmined;
            x = (Math.round(x * 10000)) / 10000;
            $('#unmined').text(x);
            $('#reward').text(data.block_reward);
            $('#nodeversion').text(data.version);
        },
        error: function(data) {
            $('.dimmer').hide();
        }
    });

    // Mempool transactions
    $.ajax({
        url: 'http://localhost:8888/webwallet-mempool',
        dataType: 'text',
        type: "GET",
        success: function(data) {
            $('#mempooltransactions').text(data);
        },
        error: function(data) {
            $('.dimmer').hide();
        }
    });

    // Sync status
    $.ajax({
        url: 'http://localhost:8888/webwallet-sync',
        dataType: 'text',
        type: "GET",
        success: function(data) {
            $('#syncstatus').text(data);
        },
        error: function(data) {
            $('.dimmer').hide();
        }
    });

}


// Draws all addresses in wallet file to page.
function drawAddresses(addresses) {
    console.log(addresses);

    viewState = 0;

    // Clear list first
    $('#walletlist').empty();

    // Loop all wallets, and present them
    var addressIndex = 0;
    $.each(addresses, function() {

        var thisAddress = this[0];
        var thisBalance = this[3];

        $('#walletlist').append(
            '<div class="event"><div class="content"><div class="summary"><div class="ui horizontal label" style="background-color:#d5a500;">'
            + addressIndex
            + '</div><b style="font-size:1.4em"><a onclick="showAddress('+ addressIndex +')">'
            + thisAddress +
            '</a></b><br>'
            + thisBalance +
            '</div></div></div><div class="ui divider"></div>'
        );

        // Increment address index id
        addressIndex += 1;
    });

    // Remove dimmer
    $('.dimmer').hide();
}

// Queries a list of all addresses from wallet, and passing to draw function to rendor to screen
function getAddresses(hideDimmer = false) {

    // Dimmer does not show for auto refreshes.
    if(hideDimmer == false) {
        $('.dimmer').show();
    }

    $('#show-wallet').hide();
    $('#show-node-stats').hide();
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



// Creates a new XMSS 8000sig address in local wallet, then refreshes addresses on page.
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







// Draws address detail to page
function drawAddress(addresses, showAddressId, addressDetail, usdvalue) {
    //console.log(addresses);
    //console.log(addressDetail);

    viewState = 1;

    // Clear list first
    $('#walletdetail').empty();

    // Get some detail about this address
    // For now we're only using the address, and signatures
    var addressIndex = 0;
    var thisAddress = '';
    var sigSplit;
    $.each(addresses, function() {

        if(addressIndex == showAddressId) {
            currentDetailAddress = showAddressId;

            thisAddress = this[0];
            var thisBalance = this[3];
            var thisType = this[2];
            var thisNonce = this[4];
            var thisSigs = this[5];

            // Split up signature result
            // signatures left: 7993 (7993/8000)
            sigSplit = thisSigs.split('(')[1]; // 7993/8000)
            sigSplit = sigSplit.split(')')[0]; // 7993/8000
            sigSplit = sigSplit.split('/'); // [0] = 7993, [1] = 8000
        }

        // Increment address index id
        addressIndex += 1;
    });


    // Show address
    $('#addressHeading').text(thisAddress);

    // Only show these details if we get a successful reply from the API
    if(addressDetail.status == "ok") {
        $('#balance').text(addressDetail.state.balance);
        $('#nonce').text(addressDetail.state.nonce);
        $('#transactions').text(addressDetail.state.transactions);
        $('#sigsremaining').text(sigSplit[0]);

        TransT.clear();
        _.each(addressDetail.transactions, function(object) {

            var txHashLink = '<a target="_blank" href="http://qrlexplorer.info/search.html#'+object.txhash+'">'+object.txhash+'</a>';

            drawTransRow(object.timestamp, object.amount, txHashLink, object.block, object.txfrom, object.txto, object.fee, addressDetail.state.address);
        });
        TransT.columns.adjust().draw(true);

        // Attempt to get USD Value of wallet
        $.ajax({
            url: 'http://cors-anywhere.herokuapp.com/https://www.folio.ninja/api/v1/quote?base=QRL&quote=USD&amount=' + addressDetail.state.balance,
            dataType: 'json',
            jsonpCallback: 'callback',
            success: function(folioNinjaReply) {
                $('#usdvalue').text("$" + folioNinjaReply.response.quote);
            }
        });

    } else {
        TransT.clear();
        $('#balance').text("0");
        $('#nonce').text("0");
        $('#transactions').text("0");
        $('#sigsremaining').text(sigSplit[0]);
        $('#usdvalue').text("0");
    }

    // Remove dimmer
    $('.dimmer').hide();
}

// Step 2 - grab details from local api
function showAddressStep2(addresses, addressIndex) {
    // Get wallet address
    var counter = 0;
    var thisAddress = '';
    $.each(addresses, function() {
        if(addressIndex == counter) {
            thisAddress = this[0];
        }
        counter += 1;
    });

    console.log(thisAddress);

    $.ajax({
        url: 'http://localhost:8080/api/address/' + thisAddress,
        success: function(addressDetail) {
            drawAddress(addresses, addressIndex, addressDetail);
        },
        error: function(addressDetail) {
            drawAddress(addresses, addressIndex, addressDetail);
        }
    });
}

// Gets details about a single address, and passes to draw function to rendor to screen.
function showAddress(addressIndex, hideDimmer = false) {

    // Dimmer does not show for auto refreshes.
    // Also don't reset data
    if(hideDimmer == false) {
        $('.dimmer').show();

        // Clear to and amount onload
        $('#to').val("");
        $('#amount').val("");
        $('#addressHeading').text("");
        $('#balance').text("");
        $('#nonce').text("");
        $('#transactions').text("");
        $('#sigsremaining').text("");
        $('#usdvalue').text("");
    }

    // Change view
    $('#show-all-wallets').hide();
    $('#show-node-stats').hide();
    $('#show-wallet').show();
    
    // Get addresses then draw
    $.ajax({
        url: 'http://localhost:8888/webwallet-addresses',
        dataType: 'json',
        type: "GET",
        success: function(addresses) {
            showAddressStep2(addresses, addressIndex);
        },
        error: function(addresses) {
            showAddressStep2(addresses, addressIndex);
        }
    });
}


// Modal to show txn result to screen
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


// Creates a transaction in the network
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
    // Hide the detail pane
    $('#show-wallet').hide();
    $('#show-node-stats').hide();

    // Rendor addresses to screen.
    getAddresses();
});


// 20 second refresh
window.setInterval(function() {
    // Refresh addresses
    if(viewState == 0) {
        getAddresses(true);
    }

    // Refresh individual address view
    if(viewState == 1) {
        showAddress(currentDetailAddress, true);
    }

    // Refresh node stats
    if(viewState == 2) {
        getNodeInfo(true);
    }
}, 20000);
