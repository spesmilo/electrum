package org.electroncash.electroncash3

import android.os.Bundle
import android.view.View
import androidx.fragment.app.DialogFragment
import androidx.fragment.app.Fragment
import androidx.lifecycle.LiveData
import androidx.lifecycle.Observer
import androidx.recyclerview.widget.RecyclerView
import com.chaquo.python.PyObject


abstract class ListFragment(fragLayout: Int, val rvId: Int) :
    Fragment(fragLayout), MainFragment {

    private val adapter by lazy { onCreateAdapter() }
    lateinit var trigger: TriggerLiveData

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        val rv = view.findViewById<RecyclerView>(rvId)
        setupVerticalList(rv)
        rv.adapter = adapter

        trigger = TriggerLiveData().apply {
            observe(viewLifecycleOwner, Observer { refresh() })
        }
    }

    abstract fun onCreateAdapter(): ListAdapter<*, *>

    fun addSource(source: LiveData<*>) =
        trigger.addSource(source)

    open fun refresh() {
        var pyList: PyObject? = null
        val wallet = daemonModel.wallet
        if (wallet != null) {
            pyList = onRefresh(wallet)
        }
        adapter.submitPyList(pyList)
    }

    /* Returns a Python sequence whose elements can be passed to ListAdapter.newModel. */
    abstract fun onRefresh(wallet: PyObject): PyObject
}


interface ListModel {
    val dialogArguments: Bundle
}


class ListAdapter<ModelType: ListModel, DialogType: DialogFragment>(
    val listFragment: Fragment, itemLayout: Int, val newModel: (PyObject) -> ModelType,
    val newDialog: () -> DialogType
) : BoundAdapter<ModelType>(itemLayout) {

    var reversed = false

    fun submitPyList(pyList: PyObject?) {
        if (pyList == null) {
            submitList(null)
        } else {
            var list = pyList.asList()
            if (reversed) {
                list = list.asReversed()
            }
            submitList(object : AbstractList<ModelType>() {
                override val size by lazy { list.size }
                override fun get(index: Int) = newModel(list.get(index))
            })
        }
    }

    override fun onBindViewHolder(holder: BoundViewHolder<ModelType>, position: Int) {
        super.onBindViewHolder(holder, position)
        holder.itemView.setOnClickListener {
            showDialog(listFragment, newDialog().apply {
                arguments = holder.item.dialogArguments
            })
        }
    }
}
