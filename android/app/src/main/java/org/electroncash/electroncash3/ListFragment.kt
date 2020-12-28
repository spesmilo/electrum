package org.electroncash.electroncash3

import android.os.Bundle
import android.view.View
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.lifecycle.Observer
import androidx.lifecycle.ViewModel
import androidx.recyclerview.widget.RecyclerView
import com.chaquo.python.PyObject


// When synchronizing, updates will come in constantly. Avoid refreshing more often than
// necessary, as lock contention may slow the synchronization process down.
val MIN_REFRESH_INTERVAL = 1000L


class ListModel : ViewModel() {
    var started = false
    val trigger = TriggerLiveData()

    /* Returns a Python sequence whose elements can be passed to ListAdapter.newModel. */
    val data = BackgroundLiveData<Unit, PyObject>()
    }


abstract class ListFragment(fragLayout: Int, val rvId: Int) :
    Fragment(fragLayout), MainFragment {

    val wallet = daemonModel.wallet!!
    private val model: ListModel by viewModels()
    private val adapter by lazy { onCreateAdapter() }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (!model.started) {
            model.started = true
            model.data.addSource(model.trigger) {
                model.data.refresh(Unit)
            }
            model.data.minInterval = MIN_REFRESH_INTERVAL
            onListModelCreated(model)
        }
    }

    abstract fun onListModelCreated(listModel: ListModel)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        val rv = view.findViewById<RecyclerView>(rvId)
        setupVerticalList(rv)
        rv.adapter = adapter
        model.data.observe(viewLifecycleOwner, Observer {
            adapter.submitPyList(wallet, it)
        })
    }

    abstract fun onCreateAdapter(): ListAdapter<*, *>
}


class ListAdapter<ModelType: ListItemModel, DialogType: DetailDialog> (
    val listFragment: ListFragment, itemLayout: Int,
    val newModel: (PyObject, PyObject) -> ModelType,
    val newDialog: () -> DialogType
) : BoundAdapter<ModelType>(itemLayout) {

    var reversed = false

    fun submitPyList(wallet: PyObject, pyList: PyObject?) {
        if (pyList == null) {
            submitList(null)
        } else {
            val list = pyList.asList()
            submitList(object : AbstractList<ModelType>() {
                override val size by lazy { list.size }
                override fun get(index: Int) =
                    newModel(wallet,
                             list.get(if (reversed) size - index - 1
                                      else index))
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


abstract class ListItemModel(val wallet: PyObject) {
    abstract val dialogArguments: Bundle
}


abstract class DetailDialog : AlertDialogFragment() {
    val listFragment by lazy { targetFragment as ListFragment }
    val wallet by lazy { listFragment.wallet }
}