package org.electroncash.electroncash3

import android.arch.lifecycle.Observer
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import kotlinx.android.synthetic.main.activity_main.*
import kotlinx.android.synthetic.main.fragment_wallets.*
import org.electroncash.electroncash3.databinding.FragmentWalletsBinding

class WalletsFragment : MainFragment() {

    val mainActivity by lazy { activity as MainActivity }
    val daemonModel by lazy { mainActivity.daemonModel }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        daemonModel.height.observe(this, Observer { height ->
            if (height != null) {
                title.value = getString(R.string.online)
                subtitle.value = "${getString(R.string.height)} $height"
            } else {
                title.value = getString(R.string.offline)
                subtitle.value = getString(R.string.cannot_send)
            }
        })
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?,
                              savedInstanceState: Bundle?): View? {
        val binding = FragmentWalletsBinding.inflate(inflater, container, false)
        binding.setLifecycleOwner(this)
        binding.daemonModel = daemonModel
        return binding.root
    }

    override fun onViewCreated(view: View?, savedInstanceState: Bundle?) {
        btnSend.setOnClickListener {
            // TODO
        }

        btnReceive.setOnClickListener {
            // TODO
            Toast.makeText(context, "Touch a receiving address to copy it to the clipboard.",
                Toast.LENGTH_SHORT).show()
            mainActivity.navigation.selectedItemId = R.id.navAddresses
        }
    }
}
